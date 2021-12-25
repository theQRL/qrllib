// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use qrllib::rustwrapper::kyber::kyber::{Kyber, SharedSecretTrait};

#[test]
fn basic_key_exchange() {
    let mut alice = Kyber::default();
    let mut bob = Kyber::default();

    let mut alice_pk = alice.get_pk();
    // Bob receives the public key, derives a secret and a response
    bob.kem_encode(alice_pk);
    let mut cypher_text = bob.get_cipher_text();

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
