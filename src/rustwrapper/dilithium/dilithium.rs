// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_traits::sign::{PublicKey as PublicKey_t, SecretKey as SecretKey_t};
use std::io::Error;

pub const CRYPTO_PUBLICKEYBYTES: usize = public_key_bytes();
pub const CRYPTO_SECRETKEYBYTES: usize = secret_key_bytes();
pub const CRYPTO_BYTES: usize = signature_bytes();

pub struct Dilithium {
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let mut pk = PublicKey::from_bytes(pk_bytes).unwrap();
        let mut sk = SecretKey::from_bytes(sk_bytes).unwrap();
        Ok(Self { pk, sk })
    }

    pub fn getPK(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn getSK(&self) -> SecretKey {
        self.sk.clone()
    }

    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        // TODO: Leon, return only signature?
        //    return std::vector<unsigned char>(message_signed.begin()+message.size(),
        //                                      message_signed.end());
        sign(message, &self.sk)
    }

    pub fn getSecretKeySize() -> usize {
        CRYPTO_SECRETKEYBYTES
    }

    pub fn getPublicKeySize() -> usize {
        CRYPTO_PUBLICKEYBYTES
    }

    pub fn sign_open(message_output: &mut &[u8], message_signed: &[u8], pk: &[u8]) -> bool {
        let message_size = message_signed.len();
        message_output.resize(message_size, 0);

        let message_output_dummy: *mut u64 = &mut 0;
        let ret = open(
            message_output.as_mut_ptr(),
            message_output_dummy,
            message_signed.as_ptr(),
            message_signed.len() as u64,
            pk.as_ptr(),
        );

        // TODO Leon: message_out has size()+CRYPTO_BYTES. Should we return just the message?
        ret == 0
    }

    pub fn extract_message(message_output: &Vec<u8>) -> Vec<u8> {
        unsafe {
            Vec::from(
                message_output
                    .as_slice()
                    .get(0..(message_output.len() - CRYPTO_BYTES as usize))
                    .unwrap(),
            )
        }
    }

    pub fn extract_signature(message_output: &Vec<u8>) -> Vec<u8> {
        unsafe {
            Vec::from(
                message_output
                    .as_slice()
                    .get((message_output.len() - CRYPTO_BYTES as usize)..(message_output.len()))
                    .unwrap(),
            )
        }
    }
}

impl Default for Dilithium {
    fn default() -> Self {
        unsafe {
            let mut pk = vec![0; CRYPTO_PUBLICKEYBYTES as usize];
            let mut sk = vec![0; CRYPTO_SECRETKEYBYTES as usize];
            sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            Dilithium { pk, sk }
        }
    }
}
