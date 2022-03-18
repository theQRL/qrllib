use hex::encode;
use qrllib::rust_wrapper::qrl::qrl_descriptor::QRLDescriptor;
use qrllib::rust_wrapper::qrl::qrl_helper;

#[test]
fn validate_address() {
    let pk: Vec<u8> = vec![0; (QRLDescriptor::get_size() + 64) as usize];

    let address = qrl_helper::get_address(&pk).unwrap();

    println!("{}", encode(&address));

    assert!(qrl_helper::address_is_valid(&address));

    let mut address2 = address.clone();
    address2[2] = 23;
    assert!(!qrl_helper::address_is_valid(&address2));

    address2 = address;
    assert!(qrl_helper::address_is_valid(&address2));

    address2[1] = 1;
    assert!(!qrl_helper::address_is_valid(&address2));
}

#[test]
fn validate_address_empty() {
    let address = Vec::new();
    println!("{}", encode(&address));

    assert!(!qrl_helper::address_is_valid(&address));
}
