// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
pub use pqcrypto_kyber::kyber768::*;
pub use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};
use std::io::Error;

pub const KYBER_PUBLICKEYBYTES: usize = public_key_bytes();
pub const KYBER_SECRETKEYBYTES: usize = secret_key_bytes();
pub const KYBER_CIPHERTEXTBYTES: usize = ciphertext_bytes();
pub const KYBER_SYMBYTES: usize = shared_secret_bytes();

#[derive(Clone)]
pub struct Kyber {
    pk: PublicKey,
    sk: SecretKey,
    ss: SharedSecret,
    ct: Ciphertext,
}

impl Kyber {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_bytes(pk_bytes).unwrap();
        let sk = SecretKey::from_bytes(sk_bytes).unwrap();
        let (ss, ct) = encapsulate(&pk);
        Ok(Self { pk, sk, ss, ct })
    }

    pub fn get_pk(&self) -> PublicKey {
        self.pk
    }

    pub fn get_sk(&self) -> SecretKey {
        self.sk
    }

    pub fn get_shared_secret(&self) -> SharedSecret {
        self.ss
    }

    pub fn get_cipher_text(&self) -> Ciphertext {
        self.ct
    }

    pub fn kem_encode(&mut self, other_pk: PublicKey) {
        let (ss, ct) = encapsulate(&other_pk);
        self.ss = ss;
        self.ct = ct;
    }

    pub fn kem_decode(&mut self, cyphertext: Ciphertext) {
        self.ss = decapsulate(&cyphertext, &self.sk);
    }
}

impl Default for Kyber {
    fn default() -> Self {
        let (pk, sk) = keypair();
        let (ss, ct) = encapsulate(&pk);
        Self { pk, sk, ss, ct }
    }
}
