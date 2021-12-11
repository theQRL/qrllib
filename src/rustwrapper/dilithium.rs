// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/dilithium_bindings.rs"));
use std::io::{Error, ErrorKind};

pub struct Dilithium {
    pk: Vec<u8>,
    sk: Vec<u8>,
}

impl Dilithium {
    pub fn new(pk: Vec<u8>, sk: Vec<u8>) -> Result<Self, Error> {
        if pk.len() != CRYPTO_PUBLICKEYBYTES as usize {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        if sk.len() != CRYPTO_SECRETKEYBYTES as usize {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        Ok(Self { pk, sk })
    }

    pub fn getPK(&self) -> Vec<u8> {
        self.pk.clone()
    }

    pub fn getSK(&self) -> Vec<u8> {
        self.sk.clone()
    }

    pub fn sign(&self, message: &Vec<u8>) -> Vec<u8> {
        let message_signed_size_dummy: *mut u64 = &mut 0;
        let mut message_signed: Vec<u8> = vec![0; message.len() + CRYPTO_BYTES as usize];

        unsafe {
            crypto_sign(
                message_signed.as_mut_ptr(),
                message_signed_size_dummy,
                message.as_ptr(),
                message.len() as u64,
                self.sk.as_ptr(),
            );

            // TODO: Leon, return only signature?
            //    return std::vector<unsigned char>(message_signed.begin()+message.size(),
            //                                      message_signed.end());
            message_signed
        }
    }

    pub fn getSecretKeySize() -> u32 {
        CRYPTO_SECRETKEYBYTES
    }

    pub fn getPublicKeySize() -> u32 {
        CRYPTO_PUBLICKEYBYTES
    }

    pub fn sign_open(message_output: &mut Vec<u8>, message_signed: &Vec<u8>, pk: &Vec<u8>) -> bool {
        let message_size = message_signed.len();
        message_output.resize(message_size, 0);

        let message_output_dummy: *mut u64 = &mut 0;
        unsafe {
            let ret = crypto_sign_open(
                message_output.as_mut_ptr(),
                message_output_dummy,
                message_signed.as_ptr(),
                message_signed.len() as u64,
                pk.as_ptr(),
            );

            // TODO Leon: message_out has size()+CRYPTO_BYTES. Should we return just the message?
            ret == 0
        }
    }

    pub fn extract_message(message_output: &Vec<u8>) -> Vec<u8> {
        Vec::from(
            message_output
                .as_slice()
                .get(0..(message_output.len() - CRYPTO_BYTES as usize))
                .unwrap(),
        )
    }

    pub fn extract_signature(message_output: &Vec<u8>) -> Vec<u8> {
        Vec::from(
            message_output
                .as_slice()
                .get((message_output.len() - CRYPTO_BYTES as usize)..(message_output.len()))
                .unwrap(),
        )
    }
}

impl Default for Dilithium {
    fn default() -> Self {
        let mut pk = vec![0; CRYPTO_PUBLICKEYBYTES as usize];
        let mut sk = vec![0; CRYPTO_SECRETKEYBYTES as usize];
        unsafe {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        };
        Dilithium { pk, sk }
    }
}
