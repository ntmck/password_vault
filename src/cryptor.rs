//! Encrypt/Decrypt sourced from -> https://github.com/DaGenix/rust-crypto/blob/master/examples/symmetriccipher.rs

extern crate crypto;
extern crate rand;
use rand::Rng;
use crypto::{ symmetriccipher, buffer, aes, blockmodes, scrypt };
use crypto::scrypt::ScryptParams;

use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub struct Cryptor;
impl Cryptor {
    pub fn scrypt_simple(password: &str, salt: &[u8]) -> [u8; 32] {
        let mut key: [u8; 32] = [0; 32];
        scrypt::scrypt(password.as_bytes(), salt, &ScryptParams::new(16, 8, 1), &mut key);
        key
    }

    pub fn encrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        let mut encryptor = aes::cbc_encryptor(
                aes::KeySize::KeySize256,
                key,
                iv,
                blockmodes::PkcsPadding);
    
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    
        loop {
            let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;
    
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
    
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
    
        Ok(final_result)
    }
    
    pub fn decrypt(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
        let mut decryptor = aes::cbc_decryptor(
                aes::KeySize::KeySize256,
                key,
                iv,
                blockmodes::PkcsPadding);
    
        let mut final_result = Vec::<u8>::new();
        let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
        let mut buffer = [0; 4096];
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    
        loop {
            let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
            final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
            match result {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => { }
            }
        }
    
        Ok(final_result)
    }

    pub fn test_crypt() {
        let message = "Hello World!";

        let mut key: [u8; 32] = [0; 32]; //keys MUST be 32 bit.
        let mut iv: [u8; 16] = [0; 16];
    
        let mut rng = rand::thread_rng();
        rng.try_fill(&mut key);
        rng.try_fill(&mut iv);
    
        let encrypted_data = Cryptor::encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
        let decrypted_data = Cryptor::decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();
    
        assert!(message.as_bytes() == &decrypted_data[..]);
    }
}