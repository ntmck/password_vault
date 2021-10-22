use std::fs;
use std::fs::OpenOptions;
use std::io::{Write, Read};
use std::vec::Vec;
use std::str;

extern crate rand;
use rand::Rng;

extern crate json;
use json::JsonValue;
use json::object;

mod cryptor;
pub use cryptor::*;

const DIR_ROOT: &'static str = "vault";
const DIR_VF: &'static str = "/_vf";
const DIR_CONTAINER: &'static str = "/container";
const SALT: [u8; 16] = [0x64,0x34,0x37,0x46,0x48,0x47,0x66,0x33,0x32,0x34,0x55,0x4a,0x3f,0x21,0x44,0x4b];
const DEF_IV: [u8; 16] = [0x42,0x18,0x45,0xe4,0x12,0xa5,0xc6,0x22,0x1a,0xde,0x8e,0xef,0x83,0x05,0x80,0x63];

//Validity file is comprised of an encrypted password validity check and an encrypted initialization vector.
//The encrypted initialization vector is what is used to decrypt the container file. Both requiring the same key.

#[derive(Debug)]
enum ErrVault {
    PasswordNotValid,
    FileNotFound,
}

fn read_validity_file(dir_path: &str, key: &[u8]) -> Result<Vec<u8>, ErrVault> {
    match OpenOptions::new().read(true).open(dir_path) {
        Ok(mut vf) => {
            let mut buffer: Vec<u8> = vec![];
            vf.read_to_end(&mut buffer);
            let decrypted = Cryptor::decrypt(&buffer[..], key, &DEF_IV).unwrap();
            if decrypted[0..5] == [0x76,0x61,0x6c,0x69,0x64] { //"valid"
                Ok(decrypted[5..].to_vec()) //initialization vector
            } else {
                Err(ErrVault::PasswordNotValid)
            }
        },
        Err(_) => {
            Err(ErrVault::FileNotFound)
        }
    }
}

fn write_validity_file(dir_path: &str, key: &[u8], iv: &[u8]) {
    if let Ok(mut vf) = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dir_path) {
            let mut contents: Vec<u8> = Vec::new();
            contents.extend_from_slice(b"valid");
            contents.extend_from_slice(iv);
            let encrypted = Cryptor::encrypt(&contents[..], key, &DEF_IV).unwrap();
            vf.write(&encrypted[..]);
    } else {
        println!("Validity file already present.\n");
    }
}

/// Creates an inner password storage directory keyed by a password via a validity file.
fn create_vault_if_not_exists(key: &[u8]) -> Result<(), std::io::Error> {
    fs::create_dir(DIR_ROOT)?;
    println!("Password vault not found. Creating new vault using the given password.\n");
    let mut iv: [u8; 16] = [0; 16];
    let mut rng = rand::thread_rng();
    rng.try_fill(&mut iv);
    write_validity_file(&format!("{}{}", DIR_ROOT, DIR_VF), &key, &iv);
    Ok(())
}

//Returns a key from given user password and the validity file's initialization vector.
fn get_password_key_and_iv(key: &mut [u8; 32]) -> Vec<u8> {
    loop {
        println!("Enter the vault password. If a password vault does not exist, one will be created with the password you provide.\n");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).expect("read_line failed.");

        println!("Processing password. This may take a few seconds.\n");
        *key = Cryptor::scrypt_simple(&input, &SALT);

        create_vault_if_not_exists(key);
        match read_validity_file(&format!("{}{}", DIR_ROOT, DIR_VF), key) {
            Ok(vf_iv) => {
                println!("Password accepted.\n");
                return vf_iv;
            },
            Err(e) => println!("Error: {:#?}\n", e),
        }
    }
}

fn write_new_encrypted_json_if_not_exists(key: &[u8], iv: &[u8]) {
    if let Ok(mut f) = OpenOptions::new().create_new(true).write(true).open(&format!("{}{}", DIR_ROOT, DIR_CONTAINER)) {
        let encrypted_f = Cryptor::encrypt(b"{\"entries\": []}", &key, &iv).unwrap(); // {"entries": []} is default. json objects will be in array. [{site, user/email, password}, ... ]
        f.write(&encrypted_f[..]);
    }
}

fn decrypt_and_json_parse_password_container(key: &[u8], iv: &[u8]) -> JsonValue {
    //Get the encrypted file's bytes.
    let mut encrypted_file = OpenOptions::new().create(true).read(true).write(true).open(&format!("{}{}", DIR_ROOT, DIR_CONTAINER)).expect("Error reading file.");
    let mut encrypted_utf8_json: Vec<u8> = vec![];
    encrypted_file.read_to_end(&mut encrypted_utf8_json);

    //Decrypt and parse the json file from the encrypted utf8 bytes.
    json::parse(
        &std::str::from_utf8(
            &Cryptor::decrypt(&encrypted_utf8_json[..], &key, &iv).expect("Could not decrypt file.")
        ).expect("Could not parse utf8 bytes.")
    ).expect("json failed to parse.")
}

fn get_user_input() -> String {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).expect("read_line failed.");

    //remove stdio garbage appended to the input string.
    input.pop();
    input.pop();
    input
}

fn remove_entry(json: &mut JsonValue) {
    println!("\nEnter the website url you would like to remove.");
    println!("\tNote: This will only remove the FIRST OCCURANCE of the url.");
    let url = get_user_input();

    let mut i = 0;
    let mut found = false;
    for entry in json["entries"].members_mut() {
        if entry["url"].as_str().unwrap().as_bytes() == url.as_bytes() { //byte array comparison is more reliable in this situation.
            found = true;
            break;
        }
        i += 1;
    }
    if found {
        json["entries"].array_remove(i);
    }
}

fn add_entry(json: &mut JsonValue) {
    println!("\nEnter the website url you are registering for:");
    let url = get_user_input();
    println!("Enter the email/username you are registering with:");
    let username = get_user_input();
    println!("Enter the password you wish to register with:");
    let password = get_user_input();

    let entry = object!{
        url: url,
        username: username,
        password: password
    };

    json["entries"].push(entry);
    println!("Entry added.");
}

fn overwrite_container(json: &JsonValue, key: &[u8], iv: &[u8]) {
    if let Ok(mut f) = OpenOptions::new().truncate(true).write(true).open(&format!("{}{}", DIR_ROOT, DIR_CONTAINER)) {
        let encrypted_f = Cryptor::encrypt(json.dump().as_bytes(), &key, &iv).unwrap(); // {"entries": []} is default. json objects will be in array. [{site, user/email, password}, ... ]
        f.write(&encrypted_f[..]);
    } else { panic!("Critical error. Failed to overwrite container."); }
}

fn main() {
    let mut key: [u8; 32] = [0; 32];
    let iv: Vec<u8> = get_password_key_and_iv(&mut key);
    write_new_encrypted_json_if_not_exists(&key, &iv[..]);
    let mut decrypted_json = decrypt_and_json_parse_password_container(&key, &iv[..]);
    
    //Get user input to display or write password entries.
    loop {
        println!("\nType an option and then press enter to select the option.\nOptions:\n\t1 -> display all entries.\n\t2 -> add a new entry.\n\t3 -> remove entry by its url.\n\tquit -> stop program and write changes.\n");

        match get_user_input().as_str() {
            "1" => println!("{}", decrypted_json.pretty(4)),
            "2" => add_entry(&mut decrypted_json),
            "3" => remove_entry(&mut decrypted_json),
            "quit" => {
                overwrite_container(&decrypted_json, &key, &iv);
                break;
            },
            _ => println!("Invalid Input.\n"),
        }
    }
}
