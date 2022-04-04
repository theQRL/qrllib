use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::qrl_helper;
use qrllib::rust_wrapper::qrl::xmss_base::Sign;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBase;
use qrllib::rust_wrapper::qrl::xmss_base::XMSSBaseTrait;
use qrllib::rust_wrapper::qrl::xmss_basic::XMSSBasic;
use qrllib::rust_wrapper::xmss_alt::hash_functions::HashFunction;
const XMSS_HEIGHT: u8 = 4;

#[test]
fn instantiation() {
    let seed: Vec<u8> = vec![0; 48];

    let xmss = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let pk = xmss.get_pk();
    let sk = xmss.get_sk();

    println!();
    println!();
    println!("seed: {} bytes\n {}", seed.len(), encode(&seed));
    println!("pk  : {} bytes\n {}", pk.len(), encode(&pk));
    println!("sk  : {} bytes\n {}", sk.len(), encode(&sk));
    println!("descr: {}", encode(xmss.get_descriptor().get_bytes()));
    println!("addr : {}", encode(xmss.get_address().unwrap()));

    assert_eq!(seed, *xmss.get_seed());
    assert_eq!(
        "000000000000000000000000000000000000000000000000".to_owned()
            + "000000000000000000000000000000000000000000000000",
        encode(xmss.get_seed())
    );

    assert_eq!(
        *xmss.get_descriptor().get_hash_function(),
        HashFunction::SHA2_256
    );
    assert_eq!(
        *xmss.get_descriptor().get_addr_format_type(),
        AddrFormatType::SHA256_2X
    );

    assert_eq!("000200", encode(xmss.get_descriptor().get_bytes()));
    assert_eq!(
        "0002000000000000000000000000000000000000000000000000".to_owned()
            + "00000000000000000000000000000000000000000000000000",
        encode(xmss.get_extended_seed())
    );

    assert_eq!(51, xmss.get_extended_seed().len());

    // let s = "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback ".to_owned() +
    //                 "aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback " +
    //                 "aback aback aback aback";

    //assert_eq!(s, bin2mnemonic(xmss.get_extended_seed()));
    //assert_eq!(xmss.get_extended_seed(), mnemonic2bin(s));

    assert_eq!(
        "00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de",
        encode(xmss.get_address().unwrap()),
    );

    assert_eq!(
        "00020096e5c065cf961565169e795803c1e60f521af7a3ea0326b42aa40c0e75390e5d8f4336de",
        encode(qrl_helper::get_address(&pk).unwrap()),
    );
}

#[test]
fn signature_length() {
    let seed: Vec<u8> = vec![0; 48];

    let xmss4 = XMSSBasic::new(
        seed.clone(),
        4,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    assert_eq!(2308, xmss4.get_signature_size(None));

    let xmss6 = XMSSBasic::new(
        seed,
        6,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    assert_eq!(2372, xmss6.get_signature_size(None));
}

#[test]
fn sign() {
    let seed: Vec<u8> = vec![0; 48];

    let mut xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);
    assert_eq!(xmss.get_index(), 0);

    let signature = xmss.sign(&data_to_sign).unwrap();

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );
    assert_eq!(xmss.get_index(), 1);

    let signature2 = xmss.sign(&data_to_sign).unwrap();

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature2.len(),
        encode(&signature2)
    );

    assert_ne!(encode(signature), encode(signature2));
    assert_eq!(xmss.get_index(), 2);
}

#[test]
fn verify() {
    let mut seed: Vec<u8> = (0..48).collect();

    let mut xmss = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::SHA2_256,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);

    let pk = xmss.get_pk();
    let sk = xmss.get_sk();
    println!();
    println!("seed:{} bytes\n{}", seed.len(), encode(seed));
    println!("pk  :{} bytes\n{}", pk.len(), encode(&pk));
    println!("sk  :{} bytes\n{}", sk.len(), encode(&sk));

    let mut signature = xmss.sign(&data_to_sign).unwrap();

    assert_eq!(Vec::from(data), data_to_sign);

    println!();
    println!();
    println!("data       :{} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(&signature)
    );

    assert!(XMSSBase::verify(&mut data_to_sign, &signature.clone(), &pk, None).is_ok());

    signature[1] += 1;
    assert!(XMSSBase::verify(&mut data_to_sign, &signature, &xmss.get_pk(), None).is_err());
}
