// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_traits::sign::{
    PublicKey as PublicKey_t, SecretKey as SecretKey_t, SignedMessage as SignedMessage_t,
    VerificationError,
};
use pqcrypto_traits::Error;

pub const CRYPTO_PUBLICKEYBYTES: usize = public_key_bytes();
pub const CRYPTO_SECRETKEYBYTES: usize = secret_key_bytes();
pub const CRYPTO_BYTES: usize = signature_bytes();

pub struct Dilithium {
    pk: PublicKey,
    sk: SecretKey,
}

impl Dilithium {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_bytes(pk_bytes).unwrap();
        let sk = SecretKey::from_bytes(sk_bytes).unwrap();
        Ok(Self { pk, sk })
    }

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn get_sk(&self) -> SecretKey {
        self.sk.clone()
    }

    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        // TODO: Leon, return only signature?
        //    return std::vector<unsigned char>(message_signed.begin()+message.size(),
        //                                      message_signed.end());
        sign(message, &self.sk)
    }

    pub fn get_secret_key_size() -> usize {
        CRYPTO_SECRETKEYBYTES
    }

    pub fn get_public_key_size() -> usize {
        CRYPTO_PUBLICKEYBYTES
    }

    pub fn sign_open(
        message_signed: &SignedMessage,
        pk: &PublicKey,
    ) -> Result<Vec<u8>, VerificationError> {
        open(message_signed, pk)
    }

    pub fn extract_message(message_output: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let valid_message_output = SignedMessage::from_bytes(message_output.as_slice())?;
        Ok(Vec::from(
            valid_message_output
                .as_bytes()
                .get(0..(valid_message_output.len() - CRYPTO_BYTES as usize))
                .unwrap(),
        ))
    }

    pub fn extract_signature(message_output: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let valid_message_output = SignedMessage::from_bytes(message_output.as_slice())?;
        Ok(Vec::from(
            valid_message_output
                .as_bytes()
                .get((message_output.len() - CRYPTO_BYTES as usize)..(message_output.len()))
                .unwrap(),
        ))
    }
}

impl Default for Dilithium {
    fn default() -> Self {
        let (pk, sk) = keypair();
        Dilithium { pk, sk }
    }
}
