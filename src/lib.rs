#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("qrllib/src/kyber/kyber.h");

        type Kyber;
        fn Kyber() -> &'static Kyber;
        fn getPK(&self) -> &CxxVector<u8>;
        fn getMyKey(&self) -> &CxxVector<u8>;
        fn getCypherText(&self) -> &CxxVector<u8>;
        fn kem_encode(&self, other_pk: &CxxVector<u8>) -> bool;
        fn kem_decode(&self, cyphertext: &CxxVector<u8>) -> bool;
    }
}



#[test]
fn round_trip_compression_decompression() {
    unsafe {
        let alice = ffi::Kyber();
        let bob = ffi::Kyber();
        
        let alice_pk = alice.getPK();
        // Bob receives the public key, derives a secret and a response
        bob.kem_encode(&alice_pk);
        let cypherText = bob.getCypherText();

        // Bob sends the cyphertext to Alice
        let valid = alice.kem_decode(&cypherText);
        assert!(valid);

        // Now Alice and Bob share the same key
        let aliceKey = alice.getMyKey();
        let bobKey = bob.getMyKey();

        for i in 0..aliceKey.len() {
            assert_eq!(aliceKey.get(i), bobKey.get(i));
        }
    }
}
