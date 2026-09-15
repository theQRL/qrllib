// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use hex::encode;
use qrllib::rust_wrapper::shasha::shasha::sha2_256;

#[test]
fn hashing_test() {
    let input = String::from("This is a test X").into_bytes();
    let output_hashed = sha2_256(&input);

    assert_eq!(input.len(), 16);
    assert_eq!(output_hashed.len(), 32);
    assert_eq!(encode(&input), "54686973206973206120746573742058");
    assert_eq!(
        encode(&output_hashed),
        "a11609b2cc5f26619fcc865473246c9ac59861383a3c4edd2433230258afa03b",
    );
}

#[test]
fn standard_and_padding_boundary_vectors() {
    let cases = [
        (
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            vec![b'a'; 55],
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            vec![b'a'; 56],
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            vec![b'a'; 63],
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        ),
        (
            vec![b'a'; 64],
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
        (
            vec![b'a'; 65],
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        ),
        (
            (0u8..=255).collect(),
            "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880",
        ),
    ];

    for (input, expected) in cases {
        assert_eq!(
            encode(sha2_256(&input)),
            expected,
            "input size {}",
            input.len()
        );
    }
}
