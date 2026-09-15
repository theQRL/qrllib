// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
pub use pqcrypto_kyber::kyber768::*;
pub use pqcrypto_traits::kem::{
    Ciphertext as CiphertextTrait, PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait,
    SharedSecret as SharedSecretTrait,
};
use std::{
    io::{Error, ErrorKind},
    mem::{size_of, MaybeUninit},
    ptr,
    sync::atomic::{compiler_fence, Ordering},
};

pub const KYBER_PUBLICKEYBYTES: usize = public_key_bytes();
pub const KYBER_SECRETKEYBYTES: usize = secret_key_bytes();
pub const KYBER_CIPHERTEXTBYTES: usize = ciphertext_bytes();
pub const KYBER_SYMBYTES: usize = shared_secret_bytes();

pub struct Kyber {
    pk: PublicKey,
    // Heap storage keeps long-lived secret bytes at stable addresses when the
    // wrapper moves. The storage destructors wipe before deallocation.
    sk: SecretKeyStorage,
    ss: SharedSecretStorage,
    ct: Ciphertext,
}

fn wipe_value<T>(value: &mut T) {
    // The pinned pqcrypto-kyber 0.7.4 key and shared-secret types are fixed
    // byte arrays without Drop implementations. Restrict this helper's uses
    // below to those two types, for which an all-zero value is valid.
    let bytes = value as *mut T as *mut u8;
    for offset in 0..size_of::<T>() {
        unsafe { ptr::write_volatile(bytes.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn copy_to_box<T: Copy>(source: &T) -> Box<T> {
    // Allocate the destination without first materializing a T-sized stack
    // value. This uses APIs available at the crate's Rust 1.78 floor; the
    // equivalent Box::new_uninit API was not stabilized until Rust 1.82.
    let destination = Box::new(MaybeUninit::<T>::uninit());
    let raw = Box::into_raw(destination) as *mut T;
    unsafe {
        ptr::copy_nonoverlapping(source, raw, 1);
        Box::from_raw(raw)
    }
}

struct SecretKeyStorage(Box<SecretKey>);

impl SecretKeyStorage {
    fn as_ref(&self) -> &SecretKey {
        self.0.as_ref()
    }
}

impl Clone for SecretKeyStorage {
    fn clone(&self) -> Self {
        // Copy directly between heap allocations. Box::new(*key) causes the
        // optimizer to stage this 2.4 KiB Copy type in an unwiped stack slot.
        Self(copy_to_box(self.as_ref()))
    }
}

impl Drop for SecretKeyStorage {
    fn drop(&mut self) {
        wipe_value(self.0.as_mut());
    }
}

struct SharedSecretStorage(Box<SharedSecret>);

impl SharedSecretStorage {
    fn as_ref(&self) -> &SharedSecret {
        self.0.as_ref()
    }

    fn as_mut(&mut self) -> &mut SharedSecret {
        self.0.as_mut()
    }
}

impl Clone for SharedSecretStorage {
    fn clone(&self) -> Self {
        Self(copy_to_box(self.as_ref()))
    }
}

impl Drop for SharedSecretStorage {
    fn drop(&mut self) {
        wipe_value(self.0.as_mut());
    }
}

impl Clone for Kyber {
    fn clone(&self) -> Self {
        Self {
            pk: self.pk,
            sk: self.sk.clone(),
            ss: self.ss.clone(),
            ct: self.ct,
        }
    }
}

impl Kyber {
    pub fn new(pk_bytes: &[u8], sk_bytes: &[u8]) -> Result<Self, Error> {
        let pk = PublicKey::from_bytes(pk_bytes).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid Kyber public key: {error:?}"),
            )
        })?;
        let mut sk = SecretKey::from_bytes(sk_bytes).map_err(|error| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("invalid Kyber secret key: {error:?}"),
            )
        })?;
        let (mut ss, ct) = encapsulate(&pk);
        let result = Self {
            pk,
            sk: SecretKeyStorage(Box::new(sk)),
            ss: SharedSecretStorage(Box::new(ss)),
            ct,
        };
        // These pqcrypto value types are Copy. Erase the source values left
        // behind after the protected object has taken its copies.
        wipe_value(&mut sk);
        wipe_value(&mut ss);
        Ok(result)
    }

    pub fn get_pk(&self) -> PublicKey {
        self.pk
    }

    pub fn get_sk(&self) -> SecretKey {
        *self.sk.as_ref()
    }

    pub fn get_shared_secret(&self) -> SharedSecret {
        *self.ss.as_ref()
    }

    pub fn get_cipher_text(&self) -> Ciphertext {
        self.ct
    }

    pub fn kem_encode(&mut self, other_pk: PublicKey) {
        let (mut ss, ct) = encapsulate(&other_pk);
        wipe_value(self.ss.as_mut());
        *self.ss.as_mut() = ss;
        self.ct = ct;
        wipe_value(&mut ss);
    }

    pub fn kem_decode(&mut self, cyphertext: Ciphertext) {
        let mut ss = decapsulate(&cyphertext, self.sk.as_ref());
        wipe_value(self.ss.as_mut());
        *self.ss.as_mut() = ss;
        wipe_value(&mut ss);
    }
}

impl Default for Kyber {
    fn default() -> Self {
        let (pk, mut sk) = keypair();
        let (mut ss, ct) = encapsulate(&pk);
        let result = Self {
            pk,
            sk: SecretKeyStorage(Box::new(sk)),
            ss: SharedSecretStorage(Box::new(ss)),
            ct,
        };
        wipe_value(&mut sk);
        wipe_value(&mut ss);
        result
    }
}
