use qrllib::rust_wrapper::qrl::qrl_descriptor::QRLDescriptor;
use qrllib::rust_wrapper::qrl::qrl_helper;

#[test]
fn validate_address() {
    let mut pk: Vec<u8> = vec![0; (QRLDescriptor::get_size() + 64) as usize];
    pk[..QRLDescriptor::get_size() as usize].copy_from_slice(&[0, 2, 0]);

    let address = qrl_helper::get_address(&pk).unwrap();

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

    assert!(!qrl_helper::address_is_valid(&address));
}

// theQRL/QRL#1816: mainnet token holder in block 1796388 with descriptor byte 0
// = 0x0c (hash function 0xC). Valid under v1.2.4, so it must stay valid.
#[test]
fn validate_mainnet_address_with_unknown_hash_function() {
    let address = hex::decode(
        "0c0d00e3acde5fa627b3c0f2d723108c265f16b9667a19d811b3c99ac329028ec8abf52fc5cca6",
    )
    .unwrap();
    assert!(qrl_helper::address_is_valid(&address));

    let mut corrupted = address.clone();
    corrupted[38] ^= 0xFF;
    assert!(!qrl_helper::address_is_valid(&corrupted));
}
