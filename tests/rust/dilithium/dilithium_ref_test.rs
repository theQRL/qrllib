// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rustwrapper::dilithium::dilithium::{
    crypto_sign, crypto_sign_keypair, crypto_sign_open, randombytes, CRYPTO_BYTES,
    CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};

#[test]
fn sign_keypair() {
    let mut message: Vec<u8> = Vec::with_capacity(100);
    unsafe {
        let mut pk: Vec<u8> = Vec::with_capacity(CRYPTO_PUBLICKEYBYTES as usize);
        let mut sk: Vec<u8> = Vec::with_capacity(CRYPTO_SECRETKEYBYTES as usize);

        let mut message_signed: Vec<u8> = Vec::with_capacity(message.len() + CRYPTO_BYTES as usize);
        let mut message2: Vec<u8> = Vec::with_capacity(message.len() + CRYPTO_BYTES as usize);

        // Generate a random message
        randombytes(message.as_mut_ptr(), message.len());

        // Generate random public/secret keys
        crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

        // Sign message
        let mut message_signed_size_dummy: *mut u64 = &mut 0;
        crypto_sign(
            message_signed.as_mut_ptr(),
            message_signed_size_dummy,
            message.as_ptr(),
            message.len() as u64,
            sk.as_ptr(),
        );

        message_signed.set_len(*message_signed_size_dummy as usize);

        assert_eq!(
            message_signed_size_dummy.as_ref(),
            Some(&(message_signed.len() as u64))
        );

        // Sign open
        let message2_size_dummy: *mut u64 = &mut 0;

        crypto_sign_open(
            message2.as_mut_ptr(),
            message2_size_dummy,
            message_signed.as_ptr(),
            message_signed.len() as u64,
            pk.as_ptr(),
        );

        for (i, element) in message.iter().enumerate() {
            assert_eq!(*element, message2[i]);
        }
    }
}
