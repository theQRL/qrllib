// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/kyber_bindings.rs"));
use std::io::{Error, ErrorKind};

#[derive(Clone)]
pub struct Kyber {
    pk: Vec<u8>,
    sk: Vec<u8>,
    key: Vec<u8>,
    ct: Vec<u8>,
}

impl Kyber {
    pub fn new(pk: Vec<u8>, sk: Vec<u8>) -> Result<Self, Error> {
        if pk.len() != KYBER_PUBLICKEYBYTES as usize {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        if sk.len() != KYBER_SECRETKEYBYTES as usize {
            return Err(Error::from(ErrorKind::InvalidInput));
        }

        Ok(Self {
            pk,
            sk,
            key: Vec::<u8>::new(),
            ct: Vec::<u8>::new(),
        })
    }

    pub fn getPK(&self) -> Vec<u8> {
        self.pk.clone()
    }

    pub fn getSK(&self) -> Vec<u8> {
        self.sk.clone()
    }

    pub fn getMyKey(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn getCypherText(&self) -> Vec<u8> {
        self.ct.clone()
    }

    pub fn kem_encode(&mut self, other_pk: &mut Vec<u8>) -> bool {
        // TODO: Verify sizes (other_pk)
        self.key.resize(KYBER_SYMBYTES as usize, 0);
        self.ct.resize(KYBER_CIPHERTEXTBYTES as usize, 0);

        unsafe {
            let validation_error = crypto_kem_enc(
                self.ct.as_mut_ptr(),
                self.key.as_mut_ptr(),
                other_pk.as_mut_ptr(),
            );
            return validation_error == 0;
        }
    }

    pub fn kem_decode(&mut self, cyphertext: &mut Vec<u8>) -> bool {
        // TODO: Verify sizes (cyphertext)
        self.key.resize(KYBER_SYMBYTES as usize, 0);

        unsafe {
            let validation_error = crypto_kem_dec(
                self.key.as_mut_ptr(),
                cyphertext.as_mut_ptr(),
                self.sk.as_mut_ptr(),
            );
            return validation_error == 0;
        }
    }
}

impl Default for Kyber {
    fn default() -> Self {
        let mut pk = vec![0; KYBER_PUBLICKEYBYTES as usize];
        let mut sk = vec![0; KYBER_SECRETKEYBYTES as usize];
        unsafe {
            crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        };
        Kyber {
            pk,
            sk,
            key: Vec::<u8>::new(),
            ct: Vec::<u8>::new(),
        }
    }
}
