// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rustwrapper::kyber::kyber::{
    crypto_kem_dec, crypto_kem_enc, crypto_kem_keypair, KYBER_CIPHERTEXTBYTES,
    KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_SYMBYTES,
};

#[test]
fn test_decode() {
    unsafe {
        // Verify constants for 768
        assert_eq!(1088, KYBER_PUBLICKEYBYTES);
        assert_eq!(1152, KYBER_CIPHERTEXTBYTES);
        assert_eq!(2400, KYBER_SECRETKEYBYTES);

        // Based on reference implementation
        let mut key_a: Vec<u8> = vec![0; KYBER_SYMBYTES as usize];
        let mut send_b: Vec<u8> = vec![0; KYBER_CIPHERTEXTBYTES as usize];
        let mut sk_a: Vec<u8> = vec![0; KYBER_SECRETKEYBYTES as usize];

        let expected_key_a: Vec<u8> = vec![
            160, 158, 123, 88, 195, 221, 144, 132, 239, 112, 79, 27, 129, 240, 212, 8, 26, 81, 138,
            214, 114, 135, 124, 174, 183, 114, 186, 220, 103, 23, 227, 88,
        ];

        //Alice uses Bobs response to get her secret key
        crypto_kem_dec(key_a.as_mut_ptr(), send_b.as_ptr(), sk_a.as_ptr());

        for i in 0..(KYBER_SYMBYTES as usize) {
            assert_eq!(expected_key_a[i], key_a[i]);
        }
    }
}

#[test]
fn test_encode_decode() {
    unsafe {
        // Verify constants for 768
        assert_eq!(1088, KYBER_PUBLICKEYBYTES);
        assert_eq!(1152, KYBER_CIPHERTEXTBYTES);
        assert_eq!(2400, KYBER_SECRETKEYBYTES);

        // Based on reference implementation
        let mut pk: Vec<u8> = vec![0; KYBER_PUBLICKEYBYTES as usize];
        let mut sk_a: Vec<u8> = vec![0; KYBER_SECRETKEYBYTES as usize];

        let mut key_a: Vec<u8> = vec![0; KYBER_SYMBYTES as usize];
        let mut key_b: Vec<u8> = vec![0; KYBER_SYMBYTES as usize];
        let mut send_b: Vec<u8> = vec![0; KYBER_CIPHERTEXTBYTES as usize];

        //Alice generates a public key
        crypto_kem_keypair(pk.as_mut_ptr(), sk_a.as_mut_ptr());

        //Bob derives a secret key and creates a response
        crypto_kem_enc(send_b.as_mut_ptr(), key_b.as_mut_ptr(), pk.as_mut_ptr());

        //Alice uses Bobs response to get her secret key
        let validation_error =
            crypto_kem_dec(key_a.as_mut_ptr(), send_b.as_mut_ptr(), sk_a.as_mut_ptr());

        assert_eq!(0, validation_error);

        for i in 0..(KYBER_SYMBYTES as usize) {
            assert_eq!(key_a[i], key_b[i]);
        }
    }
}
