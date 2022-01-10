// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use hex::encode;
use qrllib::rust_wrapper::shasha::shasha::sha2_256;

#[test]
fn hashing_test() {
    let mut input = String::from("This is a test X").into_bytes();
    let count = input.len();
    let mut output_hashed = sha2_256(&input);

    assert_eq!(input.len(), 16);
    assert_eq!(output_hashed.len(), 32);
    assert_eq!(encode(input), "54686973206973206120746573742058");
    assert_eq!(
        encode(output_hashed),
        "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b",
    );
}
