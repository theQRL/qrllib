use pqcrypto_traits::sign::SignedMessage;
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rustwrapper::dilithium::dilithium::Dilithium;

#[test]
fn sign_keypair() {
    let message: Vec<u8> = vec![0, 1, 2, 4, 6, 9, 1];

    let dilithium = Dilithium::default();

    let message_signed = dilithium.sign(&message);

    let mut message_out: Vec<u8> = Vec::with_capacity(message.len() as usize);
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
