use std::hash::Hash;

use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::qrl_helper;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBase;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBaseTrait;
use qrllib::rust_wrapper::qrl::xmss_base::TKEY;
use qrllib::rust_wrapper::qrl::xmss_base::TMESSAGE;
use qrllib::rust_wrapper::qrl::xmss_base::TSIGNATURE;
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::qrl::xmss_fast::XMSSFast;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;
const XMSS_HEIGHT: u8 = 8;

#[test]
fn instantiation() {
    let seed: Vec<u8> = vec![0; 48];

    let xmss = XMSSFast::new(
        seed.clone(),
        XMSS_HEIGHT,
        Some(HashFunction::SHA2_256),
        None,
        None,
    )
    .unwrap();

    let pk = xmss.base.get_pk();
    let sk = xmss.base.get_sk();

    println!();
    println!();
    println!("seed: {} bytes\n {}", seed.len(), encode(&seed));
    println!("pk  : {} bytes\n {}", pk.len(), encode(&pk));
    println!("sk  : {} bytes\n {}", sk.len(), encode(&sk));

    assert_eq!(seed, *xmss.base.get_seed());
}

#[test]
fn signature_length() {
    let seed: Vec<u8> = vec![0; 48];

    let xmss4 = XMSSFast::new(seed.clone(), 4, Some(HashFunction::SHA2_256), None, None).unwrap();
    assert_eq!(2308, xmss4.base.get_signature_size(None));

    let xmss6 = XMSSFast::new(seed, 6, Some(HashFunction::SHA2_256), None, None).unwrap();
    assert_eq!(2372, xmss6.base.get_signature_size(None));
}

#[test]
fn sign() {
    let seed: Vec<u8> = vec![0; 48];

    let mut xmss = XMSSFast::new(
        seed.clone(),
        XMSS_HEIGHT,
        Some(HashFunction::SHA2_256),
        None,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);
    assert_eq!(xmss.base.get_index(), 0);

    let signature = xmss.sign(&mut data_to_sign).unwrap();

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );
    assert_eq!(xmss.base.get_index(), 1);

    let signature2 = xmss.sign(&mut data_to_sign).unwrap();

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature2.len(),
        encode(&signature2)
    );

    assert_ne!(encode(&signature), encode(&signature2));
    assert_eq!(xmss.base.get_index(), 2);
}

#[test]
fn verify() {
    let mut seed: Vec<u8> = (0..48).collect();

    let mut xmss = XMSSFast::new(
        seed.clone(),
        XMSS_HEIGHT,
        Some(HashFunction::SHA2_256),
        None,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);

    let pk = xmss.base.get_pk();
    let sk = xmss.base.get_sk();
    println!();
    println!("seed:{} bytes\n{}", seed.len(), encode(&seed));
    println!("pk  :{} bytes\n{}", pk.len(), encode(&pk));
    println!("sk  :{} bytes\n{}", sk.len(), encode(&sk));

    let mut signature = xmss.sign(&mut data_to_sign).unwrap();

    assert_eq!(Vec::from(data), data_to_sign);

    println!();
    println!();
    println!("data       :{} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );

    assert!(XMSSBase::verify(&mut data_to_sign, &signature.clone(), &pk, None).is_ok());

    signature[1] += 1;
    assert!(XMSSBase::verify(&mut data_to_sign, &signature, &xmss.base.get_pk(), None).is_err());
}

#[test]
fn sign_with_w4() {
    let mut seed: Vec<u8> = (0..48).collect();

    let mut xmss = XMSSFast::new(
        seed.clone(),
        XMSS_HEIGHT,
        Some(HashFunction::SHA2_256),
        None,
        None,
    )
    .unwrap();
    xmss.initialize_tree(Some(4));

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);
    assert_eq!(xmss.base.get_index(), 0);

    let mut signature = xmss.sign(&mut data_to_sign).unwrap();

    println!();
    println!();
    println!("data       :{} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );
    assert_eq!(xmss.base.get_index(), 1);

    let signature2 = xmss.sign(&mut data_to_sign).unwrap();

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature2.len(),
        encode(&signature2)
    );

    assert_ne!(encode(&signature), encode(&signature2));
    assert_eq!(xmss.base.get_index(), 2);
}

#[test]
fn verify_with_w4() {
    let mut seed: Vec<u8> = (0..48).collect();

    let mut xmss = XMSSFast::new(
        seed.clone(),
        10,
        Some(HashFunction::SHA2_256),
        None,
        Some(4),
    )
    .unwrap();

    let message = "56454c9621c549cd05c112de496ba32f";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);

    let pk = xmss.base.get_pk();
    let sk = xmss.base.get_sk();
    println!();
    println!("seed:{} bytes\n{}", seed.len(), encode(&seed));
    println!("pk  :{} bytes\n{}", pk.len(), encode(&pk));
    println!("sk  :{} bytes\n{}", sk.len(), encode(&sk));

    let mut signature = xmss.sign(&mut data_to_sign).unwrap();

    println!();
    println!();
    println!("data       :{} bytes\n{}", data.len(), encode(&data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );

    assert!(XMSSBase::verify(&mut data_to_sign, &signature.clone(), &pk, Some(4)).is_ok());
    assert!(XMSSBase::verify(
        &mut data_to_sign,
        &signature.clone(),
        &xmss.base.get_pk(),
        None
    )
    .is_err());

    signature[1] += 1;
    assert!(XMSSBase::verify(&mut data_to_sign, &signature, &xmss.base.get_pk(), Some(4)).is_err());
}

#[test]
fn sign_index_shift() {
    let mut seed: Vec<u8> = (0..48).collect();
    let height = 4;

    let mut xmss1 = XMSSBasic::new(
        seed.clone(),
        height,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    let mut xmss2 = XMSSFast::new(
        seed.clone(),
        height,
        Some(HashFunction::SHA2_256),
        None,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign1 = Vec::from(data);
    let mut data_to_sign2 = Vec::from(data);

    let idx1 = xmss1.base.set_index(1);
    let idx2 = xmss2.set_index(1);

    let mut signature1 = xmss1.sign(&mut data_to_sign1).unwrap();
    let mut signature2 = xmss2.sign(&mut data_to_sign2).unwrap();

    //assert_eq!(signature1, signature2);

    let hstr_sig1 = encode(&signature1);
    let hstr_sig2 = encode(&signature2);

    assert_eq!(hstr_sig1, hstr_sig2);
}

#[test]
fn bad_input_constructor() {
    let mut seed: Vec<u8> = (0..48).collect();
    assert!(XMSSFast::new(seed, 3, None, None, None).is_err());
}

#[test]
fn bad_input_verify() {
    let mut message: TMESSAGE = vec![0; 2];
    let mut signature: TSIGNATURE = vec![0; 48];
    let mut pk: TKEY = vec![0; 67];

    assert!(XMSSBase::verify(&mut message, &signature, &pk, None).is_err());

    let mut signature2: TSIGNATURE = vec![0; 2287];
    assert!(XMSSBase::verify(&mut message, &signature2, &pk, None).is_err());
}

#[test]
fn index_forward() {
    let mut seed: Vec<u8> = (0..48).collect();
    let mut xmss1 =
        XMSSFast::new(seed.clone(), 4, Some(HashFunction::SHA2_256), None, None).unwrap();

    xmss1.set_index(1);
    assert_eq!(1, xmss1.base.get_index());

    xmss1.set_index(2);
    assert_eq!(2, xmss1.base.get_index());

    xmss1.set_index(10);
    assert_eq!(10, xmss1.base.get_index());
}

#[test]
fn index_limit() {
    let mut seed: Vec<u8> = (0..48).collect();
    let mut xmss1 =
        XMSSFast::new(seed.clone(), 4, Some(HashFunction::SHA2_256), None, None).unwrap();

    assert!(xmss1.set_index(100).is_err());
}

#[test]
fn index_backwards() {
    let mut seed: Vec<u8> = (0..48).collect();
    let mut xmss1 =
        XMSSFast::new(seed.clone(), 4, Some(HashFunction::SHA2_256), None, None).unwrap();

    xmss1.set_index(10);
    assert_eq!(10, xmss1.base.get_index());

    assert!(xmss1.set_index(2).is_err());
}

#[test]
fn index_same() {
    let mut seed: Vec<u8> = (0..48).collect();
    let mut xmss1 =
        XMSSFast::new(seed.clone(), 4, Some(HashFunction::SHA2_256), None, None).unwrap();

    xmss1.set_index(1);
    assert_eq!(1, xmss1.base.get_index());

    xmss1.set_index(10);
    assert_eq!(10, xmss1.base.get_index());

    xmss1.set_index(10);
    assert_eq!(10, xmss1.base.get_index());
}
