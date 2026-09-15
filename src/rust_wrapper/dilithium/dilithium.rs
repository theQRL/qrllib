// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use pqcrypto_dilithium::dilithium5::*;
use pqcrypto_traits::sign::{
    PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SignedMessage as SignedMessageTrait,
    VerificationError,
};
use pqcrypto_traits::Error;
use std::{
    mem::size_of,
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

pub const CRYPTO_PUBLICKEYBYTES: usize = public_key_bytes();
pub const CRYPTO_SECRETKEYBYTES: usize = secret_key_bytes();
pub const CRYPTO_BYTES: usize = signature_bytes();

pub struct Dilithium {
    pk: PublicKey,
    // Keep the long-lived key at a stable address. Moving a Dilithium value
    // then moves only this pointer instead of copying the key bytes to a new
    // stack slot.
    sk: SecretKeyStorage,
}

fn wipe_secret_key(secret_key: &mut SecretKey) {
    // pqcrypto-dilithium 0.4.4 represents SecretKey as a fixed byte array but
    // does not erase it on drop. Volatile stores make the wipe observable to
    // the optimizer. Keep this adapter local to the pinned dependency type.
    let bytes = secret_key as *mut SecretKey as *mut u8;
    for offset in 0..size_of::<SecretKey>() {
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct SecretKeyStorage(Box<SecretKey>);

impl SecretKeyStorage {
    fn as_ref(&self) -> &SecretKey {
        self.0.as_ref()
    }
}

impl Drop for SecretKeyStorage {
    fn drop(&mut self) {
        wipe_secret_key(self.0.as_mut());
    }
}

impl Dilithium {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_bytes(pk_bytes)?;
        let mut sk = SecretKey::from_bytes(sk_bytes)?;
        let result = Self {
            pk,
            sk: SecretKeyStorage(Box::new(sk)),
        };
        // SecretKey is Copy in the pinned pqcrypto crate. Erase the source
        // value left behind after publishing the object's protected copy.
        wipe_secret_key(&mut sk);
        Ok(result)
    }

    pub fn get_pk(&self) -> PublicKey {
        self.pk.clone()
    }

    pub fn get_sk(&self) -> SecretKey {
        *self.sk.as_ref()
    }

    pub fn sign(&self, message: &[u8]) -> SignedMessage {
        // TODO: Leon, return only signature?
        //    return std::vector<unsigned char>(message_signed.begin()+message.size(),
        //                                      message_signed.end());
        sign(message, self.sk.as_ref())
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
        if message_signed.as_bytes().len() < CRYPTO_BYTES {
            return Err(VerificationError::InvalidSignature);
        }
        open(message_signed, pk)
    }

    pub fn extract_message(message_output: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let valid_message_output = SignedMessage::from_bytes(message_output.as_slice())?;
        if valid_message_output.len() < CRYPTO_BYTES {
            return Err(Error::BadLength {
                name: "signed message",
                actual: valid_message_output.len(),
                expected: CRYPTO_BYTES,
            });
        }
        Ok(valid_message_output.as_bytes()[CRYPTO_BYTES..].to_vec())
    }

    pub fn extract_signature(message_output: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let valid_message_output = SignedMessage::from_bytes(message_output.as_slice())?;
        if valid_message_output.len() < CRYPTO_BYTES {
            return Err(Error::BadLength {
                name: "signed message",
                actual: valid_message_output.len(),
                expected: CRYPTO_BYTES,
            });
        }
        Ok(valid_message_output.as_bytes()[..CRYPTO_BYTES].to_vec())
    }
}

impl Default for Dilithium {
    fn default() -> Self {
        let (pk, mut sk) = keypair();
        let result = Dilithium {
            pk,
            sk: SecretKeyStorage(Box::new(sk)),
        };
        wipe_secret_key(&mut sk);
        result
    }
}
