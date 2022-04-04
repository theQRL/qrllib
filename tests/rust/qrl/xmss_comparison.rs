use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::xmss_base::Sign;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBaseTrait;
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;
const XMSS_HEIGHT: u8 = 4;
const XMSS_SEED_SIZE: usize = 48;

#[test]
fn key_creation() {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    let xmss1: XMSSBasic = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let xmss2: XMSSFast = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();

    let pk1 = xmss1.get_pk();
    let sk1 = xmss1.get_sk();

    let pk2 = xmss2.get_pk();
    let sk2 = xmss2.get_sk();

    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
}

#[test]
fn sign() {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    let mut xmss1: XMSSBasic = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let mut xmss2: XMSSFast = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = Vec::from(data);

    let signature1 = xmss1.sign(&data_to_sign).unwrap();
    let signature2 = xmss2.sign(&data_to_sign).unwrap();

    assert_eq!(signature1, signature2);
}

#[test]
fn sign_twice() {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    let mut xmss1: XMSSBasic = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let mut xmss2: XMSSFast = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = Vec::from(data);

    let mut signature1 = xmss1.sign(&data_to_sign).unwrap();
    let mut signature2 = xmss2.sign(&data_to_sign).unwrap();
    assert_eq!(signature1, signature2);

    signature1 = xmss1.sign(&data_to_sign).unwrap();
    signature2 = xmss2.sign(&data_to_sign).unwrap();
    assert_eq!(signature1, signature2);

    let hstr_sig1 = encode(&signature1);
    let hstr_sig2 = encode(&signature2);
    assert_eq!(hstr_sig1, hstr_sig2);
}

#[test]
fn sign_three_times_vs_shift() {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    let mut xmss1: XMSSBasic = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let mut xmss2: XMSSFast = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = Vec::from(data);

    xmss1.set_index(2).unwrap();
    let signature1 = xmss1.sign(&data_to_sign).unwrap();
    xmss2.sign(&data_to_sign).unwrap();
    xmss2.sign(&data_to_sign).unwrap();
    let signature2 = xmss2.sign(&data_to_sign).unwrap();
    assert_eq!(signature1, signature2);

    let hstr_sig1 = encode(&signature1);
    let hstr_sig2 = encode(&signature2);
    assert_eq!(hstr_sig1, hstr_sig2);
}

#[test]
fn sign_index_shift() {
    let seed: Vec<u8> = vec![0; XMSS_SEED_SIZE];

    let mut xmss1: XMSSBasic = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let mut xmss2: XMSSFast = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = Vec::from(data);

    xmss1.set_index(1).unwrap();
    xmss2.set_index(1).unwrap();

    let signature1 = xmss1.sign(&data_to_sign).unwrap();
    let signature2 = xmss2.sign(&data_to_sign).unwrap();
    assert_eq!(signature1, signature2);

    let hstr_sig1 = encode(&signature1);
    let hstr_sig2 = encode(&signature2);
    assert_eq!(hstr_sig1, hstr_sig2);
}
