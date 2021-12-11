// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rustwrapper::dilithium::Dilithium;

#[test]
fn sign_keypair() {
    let message: Vec<u8> = vec![0, 1, 2, 4, 6, 9, 1];

    let dilithium = Dilithium::default();

    let message_signed = dilithium.sign(&message);

    let mut message_out: Vec<u8> = Vec::with_capacity(message.len() as usize);
    let pk = dilithium.getPK();

    let ret = Dilithium::sign_open(&mut message_out, &message_signed, &pk);

    assert!(ret);
}

#[test]
fn sign_keypair_fail() {
    let message: Vec<u8> = vec![0, 1, 2, 4, 6, 9, 1];

    let dilithium = Dilithium::default();

    let mut message_signed = dilithium.sign(&message);

    let mut message_out: Vec<u8> = Vec::with_capacity(message.len() as usize);
    let pk = dilithium.getPK();

    message_signed[3] ^= 1;

    let ret = Dilithium::sign_open(&mut message_out, &message_signed, &pk);

    assert!(!ret);
}
