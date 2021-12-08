use qrllib::rustwrapper::kyber::Kyber;

#[test]
fn basic_key_exchange() {
    let mut alice = Kyber::default();
    let mut bob = Kyber::default();

    let mut alice_pk = alice.getPK();
    // Bob receives the public key, derives a secret and a response
    bob.kem_encode(&mut alice_pk);
    let mut cypher_text = bob.getCypherText();

    // Bob sends the cyphertext to Alice
    let valid = alice.kem_decode(&mut cypher_text);
    assert!(valid);

    // Now Alice and Bob share the same key
    let alice_key = alice.getMyKey();
    let bob_key = bob.getMyKey();

    for i in 0..alice_key.len() {
        assert_eq!(alice_key.get(i), bob_key.get(i));
    }
}
