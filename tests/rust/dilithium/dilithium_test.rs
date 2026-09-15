use pqcrypto_traits::sign::{
    PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, SignedMessage,
    SignedMessage as SignedMessageTrait,
};
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rust_wrapper::dilithium::dilithium::{
    Dilithium, CRYPTO_BYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};

#[test]
fn sign_keypair() {
    let message: Vec<u8> = vec![0, 1, 2, 4, 6, 9, 1];

    let dilithium = Dilithium::default();

    let message_signed = dilithium.sign(&message);

    let pk = dilithium.get_pk();

    assert!(Dilithium::sign_open(&message_signed, &pk).is_ok());
}

#[test]
fn sign_keypair_fail() {
    let message: Vec<u8> = vec![0, 1, 2, 4, 6, 9, 1];

    let dilithium = Dilithium::default();

    let mut message_signed = Vec::from(dilithium.sign(&message).as_bytes());

    let pk = dilithium.get_pk();

    message_signed[3] ^= 1;

    let modified_message_signed = SignedMessage::from_bytes(message_signed.as_slice()).unwrap();
    assert!(Dilithium::sign_open(&modified_message_signed, &pk).is_err());
}

#[test]
fn constructor_rejects_malformed_key_lengths_without_panicking() {
    let generated = Dilithium::default();
    let pk = generated.get_pk();
    let sk = generated.get_sk();

    assert!(Dilithium::new(pk.as_bytes(), sk.as_bytes()).is_ok());

    for length in [0, CRYPTO_PUBLICKEYBYTES - 1, CRYPTO_PUBLICKEYBYTES + 1] {
        let malformed_pk = vec![0; length];
        assert!(Dilithium::new(&malformed_pk, sk.as_bytes()).is_err());
    }

    for length in [0, CRYPTO_SECRETKEYBYTES - 1, CRYPTO_SECRETKEYBYTES + 1] {
        let malformed_sk = vec![0; length];
        assert!(Dilithium::new(pk.as_bytes(), &malformed_sk).is_err());
    }
}

#[test]
fn signed_object_extraction_uses_signature_then_message_layout() {
    let message = vec![0x11, 0x22, 0x33];
    let dilithium = Dilithium::default();
    let signed = dilithium.sign(&message);
    let serialized = signed.as_bytes().to_vec();

    let signature = Dilithium::extract_signature(&serialized).unwrap();
    let extracted_message = Dilithium::extract_message(&serialized).unwrap();

    assert_eq!(signature.len(), CRYPTO_BYTES);
    assert_eq!(signature, serialized[..CRYPTO_BYTES]);
    assert_eq!(extracted_message, message);
    assert_eq!(extracted_message, serialized[CRYPTO_BYTES..]);
}

#[test]
fn signed_object_length_boundaries_return_errors_or_exact_slices() {
    for length in [0, CRYPTO_BYTES - 1] {
        let malformed = vec![0; length];
        assert!(Dilithium::extract_signature(&malformed).is_err());
        assert!(Dilithium::extract_message(&malformed).is_err());

        let parsed = SignedMessage::from_bytes(&malformed).unwrap();
        assert!(Dilithium::sign_open(&parsed, &Dilithium::default().get_pk()).is_err());
    }

    for length in [CRYPTO_BYTES, CRYPTO_BYTES + 1] {
        let serialized = vec![0; length];
        assert_eq!(
            Dilithium::extract_signature(&serialized).unwrap().len(),
            CRYPTO_BYTES
        );
        assert_eq!(
            Dilithium::extract_message(&serialized).unwrap().len(),
            length - CRYPTO_BYTES
        );
    }
}
