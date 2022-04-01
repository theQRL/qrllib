use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::xmss_base::{Sign, XMSSBaseTrait};
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;

const XMSS_HEIGHT: u8 = 4;

fn instantiation<T: XMSSBaseTrait + Sign>(xmss: T) {
    let seed: Vec<u8> = vec![0; 48];

    let pk = xmss.get_pk();
    let sk = xmss.get_sk();

    println!();
    println!();
    println!("seed: {} bytes\n {}", seed.len(), encode(&seed));
    println!("pk  : {} bytes\n {}", pk.len(), encode(&pk));
    println!("sk  : {} bytes\n {}", sk.len(), encode(&sk));

    assert_eq!(seed, *xmss.get_seed());
}

#[test]
fn xmss_fast_instantiation() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    instantiation(xmss);
}

#[test]
fn xmss_basic_instantiation() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    instantiation(xmss);
}

fn signature_len<T: XMSSBaseTrait + Sign>(xmss4: T, xmss6: T) {
    let seed: Vec<u8> = vec![0; 48];
    assert_eq!(2308, xmss4.get_signature_size(None));
    assert_eq!(2372, xmss6.get_signature_size(None));
}

#[test]
fn xmss_basic_signature_len() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss4 = XMSSBasic::new(
        seed.clone(),
        4,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let xmss6 = XMSSBasic::new(
        seed,
        6,
        HashFunction::Shake256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    signature_len(xmss4, xmss6);
}

#[test]
fn xmss_fast_signature_len() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss4 = XMSSFast::new(
        seed.clone(),
        4,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    let xmss6 = XMSSFast::new(
        seed,
        6,
        Some(HashFunction::Shake256),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    signature_len(xmss4, xmss6);
}

fn sign<T: XMSSBaseTrait + Sign>(mut xmss: T) {
    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = data.to_vec();

    let signature = xmss.sign(&data_to_sign).unwrap();

    println!();
    println!();
    println!("data: {} bytes\n {}", data.len(), encode(&data));
    println!(
        "signature: {} bytes\n {}",
        signature.len(),
        encode(&signature)
    );
}

#[test]
fn xmss_basic_sign() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    sign(xmss);
}

#[test]
fn xmss_fast_sign() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    sign(xmss);
}

fn sign_many_times_index_moves<T: XMSSBaseTrait + Sign>(mut xmss: T) {
    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = data.to_vec();

    for i in 0..10 {
        assert_eq!(i, xmss.get_index());
        let sk = xmss.get_sk();
        let pk = xmss.get_pk();
        println!("sk: {} bytes\n {}", sk.len(), encode(&sk));
        println!("pk: {} bytes\n {}", pk.len(), encode(&pk));

        let signature = xmss.sign(&data_to_sign).unwrap();
        println!(
            "signature: {} bytes\n {}",
            signature.len(),
            encode(&signature)
        );

        assert_eq!(i + 1, xmss.get_index());
    }
}

#[test]
fn xmss_basic_sign_many_times_index_moves() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    sign_many_times_index_moves(xmss);
}

#[test]
fn xmss_fast_sign_many_times_index_moves() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    sign_many_times_index_moves(xmss);
}

fn sign_many_times_signature_changes<T: XMSSBaseTrait + Sign>(mut xmss: T) {
    let message = "This is a test message";
    let data = message.as_bytes();
    let data_to_sign = data.to_vec();

    let mut prev_sig: Vec<u8> = vec![0; xmss.get_signature_size(None) as usize];
    for i in 0..10 {
        assert_eq!(i, xmss.get_index());
        let sk = xmss.get_sk();
        let pk = xmss.get_pk();
        println!("sk: {} bytes\n {}", sk.len(), encode(&sk));
        println!("pk: {} bytes\n {}", pk.len(), encode(&pk));

        let signature = xmss.sign(&data_to_sign).unwrap();
        println!(
            "signature: {} bytes\n {}",
            signature.len(),
            encode(&signature)
        );
        assert_ne!(signature, prev_sig);
        assert_eq!(i + 1, xmss.get_index());
        prev_sig = signature;
    }
}

#[test]
fn xmss_basic_sign_many_times_signature_changes() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    sign_many_times_signature_changes(xmss);
}

#[test]
fn xmss_fast_sign_many_times_signature_changes() {
    let seed: Vec<u8> = vec![0; 48];
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    sign_many_times_signature_changes(xmss);
}

fn verify<T: XMSSBaseTrait + Sign>(mut xmss: T) {
    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = data.to_vec();

    let seed = xmss.get_seed();
    let pk = xmss.get_pk();
    let sk = xmss.get_sk();
    println!();
    println!("seed: {} bytes\n {}", seed.len(), encode(&seed));
    println!("pk: {} bytes\n {}", pk.len(), encode(&pk));
    println!("sk: {} bytes\n {}", sk.len(), encode(&sk));

    let mut signature1 = xmss.sign(&data_to_sign).unwrap();

    println!("---------------------------------------------");
    println!("data: {} bytes\n {}", data.len(), encode(&data));
    println!(
        "signature: {} bytes\n {}",
        signature1.len(),
        encode(&signature1)
    );

    assert!(T::verify(&mut data_to_sign, &signature1, &pk, None).is_ok());

    let mut signature2 = xmss.sign(&data_to_sign).unwrap();
    assert_eq!(data, data_to_sign);

    println!("---------------------------------------------");
    println!("data: {} bytes\n {}", data.len(), encode(&data));
    println!(
        "signature: {} bytes\n {}",
        signature1.len(),
        encode(&signature1)
    );

    assert!(T::verify(&mut data_to_sign, &signature2, &pk, None).is_ok());

    println!("---------------------------------------------");
    println!("---------------------------------------------");
    signature1[1] += 1;
    // FIXME: This is intentionally breaking the index
    assert!(T::verify(&mut data_to_sign, &signature1, &pk, None).is_err());

    signature2[1] += 1;
    // FIXME: This is intentionally breaking the index
    assert!(T::verify(&mut data_to_sign, &signature2, &pk, None).is_err());
}

#[test]
fn xmss_basic_verify() {
    let seed: Vec<u8> = (0..48).collect();
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    verify(xmss);
}

#[test]
fn xmss_fast_verify() {
    let seed: Vec<u8> = (0..48).collect();
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    verify(xmss);
}

fn sign_verify_index_shift<T: XMSSBaseTrait + Sign>(mut xmss: T) {
    xmss.set_index(1);
    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = data.to_vec();

    let pk = xmss.get_pk();
    for i in 0..10 {
        let signature = xmss.sign(&data_to_sign).unwrap();
        println!(
            "signature: {} bytes\n {}",
            signature.len(),
            encode(&signature)
        );
        assert_eq!(data, data_to_sign);
        assert!(T::verify(&mut data_to_sign, &signature, &pk, None).is_ok());
    }
}

#[test]
fn xmss_basic_sign_verify_index_shift() {
    let seed: Vec<u8> = (0..48).collect();
    let xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    sign_verify_index_shift(xmss);
}

#[test]
fn xmss_fast_sign_verify_index_shift() {
    let seed: Vec<u8> = (0..48).collect();
    let xmss = XMSSFast::new(
        seed,
        XMSS_HEIGHT,
        Some(HashFunction::Shake128),
        Some(AddrFormatType::SHA256_2X),
        None,
    )
    .unwrap();
    sign_verify_index_shift(xmss);
}
