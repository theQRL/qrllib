use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_address_format::AddrFormatType;
use qrllib::rust_wrapper::qrl::qrl_helper;
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
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let pk = xmss.base.get_pk();
    let sk = xmss.base.get_sk();

    println!();
    println!();
    println!("seed: {} bytes\n {}", seed.len(), encode(seed.clone()));
    println!("pk  : {} bytes\n {}", pk.len(), encode(pk.clone()));
    println!("sk  : {} bytes\n {}", sk.len(), encode(sk));
    println!("descr: {}", encode(xmss.base.get_descriptor().get_bytes()));
    println!("addr : {}", encode(xmss.base.get_address().unwrap()));

    assert_eq!(seed, *xmss.base.get_seed());
    assert_eq!(
        "000000000000000000000000000000000000000000000000".to_owned()
            + "000000000000000000000000000000000000000000000000",
        encode(xmss.base.get_seed())
    );

    assert_eq!(
        *xmss.base.get_descriptor().get_hash_function(),
        HashFunction::Shake128
    );
    assert_eq!(
        *xmss.base.get_descriptor().get_addr_format_type(),
        AddrFormatType::SHA256_2X
    );

    assert_eq!("010200", encode(xmss.base.get_descriptor().get_bytes()));
    assert_eq!(
        "0102000000000000000000000000000000000000000000000000".to_owned()
            + "00000000000000000000000000000000000000000000000000",
        encode(xmss.base.get_extended_seed())
    );

    assert_eq!(51, xmss.base.get_extended_seed().len());

    let s = "absorb bunny aback aback aback aback aback aback aback aback aback aback aback aback aback ".to_owned() +
                    "aback aback aback aback aback aback aback aback aback aback aback aback aback aback aback " +
                    "aback aback aback aback";

    //assert_eq!(s, bin2mnemonic(xmss.base.get_extended_seed()));
    //assert_eq!(xmss.base.get_extended_seed(), mnemonic2bin(s));

    assert_eq!(
        "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897",
        encode(xmss.base.get_address().unwrap()),
    );

    assert_eq!(
        "01020095f03f084bcb29b96b0529c17ce92c54c1e8290193a93803812ead95e8e6902506b67897",
        encode(qrl_helper::get_address(&pk).unwrap()),
    );
}

#[test]
fn get_height_from_sig_size() {
    assert_eq!(8, XMSSBase::get_height_from_sig_size(2436, None).unwrap());
    assert_eq!(10, XMSSBase::get_height_from_sig_size(2500, None).unwrap());
    assert!(XMSSBase::get_height_from_sig_size(2437, None).is_err());
    assert!(XMSSBase::get_height_from_sig_size(1000, None).is_err());
}

#[test]
fn signature_length() {
    let seed: Vec<u8> = vec![0; 48];

    let xmss4 = XMSSBasic::new(
        seed.clone(),
        4,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    assert_eq!(2308, xmss4.base.get_signature_size(None));

    let xmss6 = XMSSBasic::new(
        seed,
        6,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();
    assert_eq!(2372, xmss6.base.get_signature_size(None));
}

#[test]
fn sign() {
    let seed: Vec<u8> = vec![0; 48];

    let mut xmss = XMSSBasic::new(
        seed,
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);
    assert_eq!(xmss.base.get_index(), 0);

    let signature = xmss.sign(&mut data_to_sign);

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(signature.clone())
    );
    assert_eq!(xmss.base.get_index(), 1);

    let signature2 = xmss.sign(&mut data_to_sign);

    println!();
    println!();
    println!("data       : {} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature2.len(),
        encode(signature2.clone())
    );

    assert_ne!(encode(signature), encode(signature2));
    assert_eq!(xmss.base.get_index(), 2);
}

#[test]
fn verify() {
    let mut seed: Vec<u8> = (0..48).collect();

    let mut xmss = XMSSBasic::new(
        seed.clone(),
        XMSS_HEIGHT,
        HashFunction::Shake128,
        AddrFormatType::SHA256_2X,
        None,
    )
    .unwrap();

    let message = "This is a test message";
    let data = message.as_bytes();
    let mut data_to_sign = Vec::from(data);

    let pk = xmss.base.get_pk();
    let sk = xmss.base.get_sk();
    println!();
    println!("seed:{} bytes\n{}", seed.len(), encode(seed));
    println!("pk  :{} bytes\n{}", pk.len(), encode(pk.clone()));
    println!("sk  :{} bytes\n{}", sk.len(), encode(sk));

    let mut signature = xmss.sign(&mut data_to_sign);

    assert_eq!(Vec::from(data), data_to_sign);

    println!();
    println!();
    println!("data       :{} bytes\n{}", data.len(), encode(data));
    println!(
        "signature  :{} bytes\n{}",
        signature.len(),
        encode(signature.clone())
    );

    assert!(XMSSBase::verify(&mut data_to_sign, &signature.clone(), &pk, None).is_ok());

    signature[1] += 1;
    assert!(XMSSBase::verify(&mut data_to_sign, &signature, &xmss.base.get_pk(), None).is_err());
}
