// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rust_wrapper::kyber::kyber::{
    Kyber, PublicKeyTrait, SecretKeyTrait, SharedSecretTrait, KYBER_PUBLICKEYBYTES,
    KYBER_SECRETKEYBYTES,
};

#[test]
fn basic_key_exchange() {
    let mut alice = Kyber::default();
    let mut bob = Kyber::default();

    let alice_pk = alice.get_pk();
    // Bob receives the public key, derives a secret and a response
    bob.kem_encode(alice_pk);
    let cypher_text = bob.get_cipher_text();

    // Bob sends the cyphertext to Alice
    alice.kem_decode(cypher_text);

    // Now Alice and Bob share the same key
    let alice_key = alice.get_shared_secret();
    let alice_key_bytes = alice_key.as_bytes();
    let bob_key = bob.get_shared_secret();
    let bob_key_bytes = bob_key.as_bytes();

    for i in 0..alice_key_bytes.len() {
        assert_eq!(alice_key_bytes.get(i), bob_key_bytes.get(i));
    }
}

#[test]
fn constructor_rejects_malformed_key_lengths_without_panicking() {
    let generated = Kyber::default();
    let pk = generated.get_pk();
    let sk = generated.get_sk();

    assert!(Kyber::new(pk.as_bytes(), sk.as_bytes()).is_ok());

    for length in [0, KYBER_PUBLICKEYBYTES - 1, KYBER_PUBLICKEYBYTES + 1] {
        let malformed_pk = vec![0; length];
        assert!(Kyber::new(&malformed_pk, sk.as_bytes()).is_err());
    }

    for length in [0, KYBER_SECRETKEYBYTES - 1, KYBER_SECRETKEYBYTES + 1] {
        let malformed_sk = vec![0; length];
        assert!(Kyber::new(pk.as_bytes(), &malformed_sk).is_err());
    }
}
