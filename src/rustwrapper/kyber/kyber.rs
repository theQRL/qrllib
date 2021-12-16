// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#![allow(dead_code)]
use libc::{c_int, c_uchar};
use std::io::{Error, ErrorKind};

pub const KYBER_K: u32 = 3;
pub const CRYPTO_ALGNAME: &str = "Kyber768";
pub const KYBER_SYMBYTES: u32 = 32; /* size in bytes of shared key, hashes, and seeds */

pub const KYBER_POLYBYTES: u32 = 416;
pub const KYBER_POLYCOMPRESSEDBYTES: u32 = 96;
pub const KYBER_POLYVECBYTES: u32 = KYBER_K * KYBER_POLYBYTES;
pub const KYBER_POLYVECCOMPRESSEDBYTES: u32 = KYBER_K * 352;

pub const KYBER_INDCPA_MSGBYTES: u32 = KYBER_SYMBYTES;
pub const KYBER_INDCPA_PUBLICKEYBYTES: u32 = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_SYMBYTES;
pub const KYBER_INDCPA_SECRETKEYBYTES: u32 = KYBER_POLYVECBYTES;
pub const KYBER_INDCPA_BYTES: u32 = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

pub const KYBER_PUBLICKEYBYTES: u32 = KYBER_INDCPA_PUBLICKEYBYTES;
pub const KYBER_SECRETKEYBYTES: u32 =
    KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2 * KYBER_SYMBYTES; /* 32 bytes of additional space to save H(pk) */
pub const KYBER_CIPHERTEXTBYTES: u32 = KYBER_INDCPA_BYTES;

#[link(name = "kyber", kind = "static")]
extern "C" {
    // #[link_name = "WRAPPED_KYBER_PUBLICKEYBYTES"]
    // pub static KYBER_PUBLICKEYBYTES: u32;
    // #[link_name = "WRAPPED_KYBER_SECRETKEYBYTES"]
    // pub static KYBER_SECRETKEYBYTES: u32;
    // #[link_name = "WRAPPED_KYBER_CIPHERTEXTBYTES"]
    // pub static KYBER_CIPHERTEXTBYTES: u32;
    pub fn crypto_kem_dec(ss: *mut c_uchar, ct: *const c_uchar, sk: *const c_uchar) -> c_int;
    pub fn crypto_kem_enc(ct: *mut c_uchar, ss: *mut c_uchar, pk: *const c_uchar) -> c_int;
    pub fn crypto_kem_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> i32;
}

#[derive(Clone)]
pub struct Kyber {
    pk: Vec<u8>,
    sk: Vec<u8>,
    key: Vec<u8>,
    ct: Vec<u8>,
}

impl Kyber {
    pub fn new(pk: Vec<u8>, sk: Vec<u8>) -> Result<Self, Error> {
        unsafe {
            if pk.len() != KYBER_PUBLICKEYBYTES as usize {
                return Err(Error::from(ErrorKind::InvalidInput));
            }

            if sk.len() != KYBER_SECRETKEYBYTES as usize {
                return Err(Error::from(ErrorKind::InvalidInput));
            }
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
        unsafe {
            // TODO: Verify sizes (other_pk)
            self.key.resize(KYBER_SYMBYTES as usize, 0);
            self.ct.resize(KYBER_CIPHERTEXTBYTES as usize, 0);

            let validation_error = crypto_kem_enc(
                self.ct.as_mut_ptr(),
                self.key.as_mut_ptr(),
                other_pk.as_mut_ptr(),
            );
            return validation_error == 0;
        }
    }

    pub fn kem_decode(&mut self, cyphertext: &mut Vec<u8>) -> bool {
        unsafe {
            // TODO: Verify sizes (cyphertext)
            self.key.resize(KYBER_SYMBYTES as usize, 0);

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
        unsafe {
            let mut pk = vec![0; KYBER_PUBLICKEYBYTES as usize];
            let mut sk = vec![0; KYBER_SECRETKEYBYTES as usize];

            crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            return Kyber {
                pk,
                sk,
                key: Vec::<u8>::new(),
                ct: Vec::<u8>::new(),
            };
        };
    }
}
