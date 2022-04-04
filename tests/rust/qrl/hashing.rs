use qrllib::rust_wrapper::qrl::hashing;
use qrllib::rust_wrapper::qrl::misc::{bin2hstr, str2bin};

use crate::rust::qrl::misc;
#[test]
fn sha2_256() {
    let input = "This is a test X";
}

#[test]
fn sha2_256_1() {
    let input = "This is a test X".to_string();

    let input_bin = str2bin(&input);
    let output_hashed = hashing::sha2_256_n(&input_bin, 1).unwrap();

    assert_eq!(input_bin.len(), 16);
    assert_eq!(output_hashed.len(), 32);

    assert_eq!(bin2hstr(&input_bin, 0), "54686973206973206120746573742058");
    assert_eq!(
        bin2hstr(&output_hashed, 0),
        "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b"
    );
}

#[test]
fn sha2_256_n() {
    let input = "This is a test X".to_string();

    let input_bin = str2bin(&input);
    let output_hashed = hashing::sha2_256_n(&input_bin, 16).unwrap();

    assert_eq!(input_bin.len(), 16);
    assert_eq!(output_hashed.len(), 32);

    assert_eq!(bin2hstr(&input_bin, 0), "54686973206973206120746573742058");
    assert_eq!(
        bin2hstr(&output_hashed, 0),
        "3be2d7e048d22de2c117465e5b4b819e764352680027c9790a53a7326d62a0fe"
    );
}

#[test]
fn shake128() {
    let input = "This is a test X".to_string();
    let hash_size = 32;

    let input_bin = str2bin(&input);
    let output_hashed = hashing::shake128(hash_size, &input_bin);

    assert_eq!(input_bin.len(), 16);
    assert_eq!(output_hashed.len(), 32);

    assert_eq!(bin2hstr(&input_bin, 0), "54686973206973206120746573742058");
    assert_eq!(
        bin2hstr(&output_hashed, 0),
        "02c7654fd239753b787067b1b75523d9bd2c39daa384e4b0d4f91eb78d2a5492"
    );
}

#[test]
fn shake256() {
    let input = "This is a test X".to_string();
    let hash_size = 32;

    let input_bin = str2bin(&input);
    let output_hashed = hashing::shake256(hash_size, &input_bin);

    assert_eq!(input_bin.len(), 16);
    assert_eq!(output_hashed.len(), 32);

    assert_eq!(bin2hstr(&input_bin, 0), "54686973206973206120746573742058");
    assert_eq!(
        bin2hstr(&output_hashed, 0),
        "b3453cb0cbd37d726a842eb750e6091b15a92efd2695e3191a96d8d07413db04"
    );
}
