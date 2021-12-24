// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use pqcrypto_kyber::kyber768::*;
use pqcrypto_traits::kem::{PublicKey as PublicKey_t, SecretKey as SecretKey_t};
use std::io::Error;

pub const KYBER_PUBLICKEYBYTES: usize = public_key_bytes();
pub const KYBER_SECRETKEYBYTES: usize = secret_key_bytes();
pub const KYBER_CIPHERTEXTBYTES: usize = ciphertext_bytes();

#[derive(Clone)]
pub struct Kyber {
    pk: PublicKey,
    sk: SecretKey,
    key: SharedSecret,
    ct: Ciphertext,
}

impl Kyber {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let mut pk = PublicKey::from_bytes(pk_bytes).unwrap();
        let mut sk = SecretKey::from_bytes(sk_bytes).unwrap();
        let (mut key, mut ct) = encapsulate(&pk);
        Ok(Self { pk, sk, key, ct })
    }

    pub fn getPK(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn getSK(&self) -> SecretKey {
        self.sk.clone()
    }

    pub fn getMyKey(&self) -> SharedSecret {
        self.key.clone()
    }

    pub fn getCypherText(&self) -> Ciphertext {
        self.ct.clone()
    }

    pub fn kem_encode(&mut self, other_pk: PublicKey) {
        let (mut key, mut ct) = encapsulate(&other_pk);
        self.key = key;
        self.ct = ct;
    }

    pub fn kem_decode(&mut self, cyphertext: Ciphertext) {
        self.key = decapsulate(&cyphertext, &self.sk);
    }
}

impl Default for Kyber {
    fn default() -> Self {
        let (mut pk, mut sk) = keypair();
        let (mut key, mut ct) = encapsulate(&pk);
        Self { pk, sk, key, ct }
    }
}
