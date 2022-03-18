use qrllib::rust_wrapper::{
    qrl::{
        qrl_address_format::AddrFormatType,
        qrl_descriptor::{self, QRLDescriptor, SignatureType},
    },
    xmss_alt::hash_functions::HashFunction,
};

#[test]
fn check_attributes_1() {
    let desc = QRLDescriptor::new(
        HashFunction::SHA2_256,
        SignatureType::XMSS,
        10,
        AddrFormatType::SHA256_2X,
    );

    assert_eq!(*desc.get_hash_function(), HashFunction::SHA2_256);
    assert_ne!(*desc.get_hash_function(), HashFunction::Shake128);
    assert_eq!(*desc.get_signature_type(), SignatureType::XMSS);

    assert_eq!(10, desc.get_height());

    let expected_descriptor_bytes: Vec<u8> = vec![0x00, 0x05, 0x00];
    assert_eq!(expected_descriptor_bytes, desc.get_bytes());
}

#[test]
fn check_attributes_2() {
    let desc = QRLDescriptor::new(
        HashFunction::Shake128,
        SignatureType::XMSS,
        16,
        AddrFormatType::SHA256_2X,
    );

    assert_ne!(*desc.get_hash_function(), HashFunction::SHA2_256);
    assert_eq!(*desc.get_hash_function(), HashFunction::Shake128);
    assert_eq!(*desc.get_signature_type(), SignatureType::XMSS);
    assert_eq!(*desc.get_addr_format_type(), AddrFormatType::SHA256_2X);
    assert_eq!(16, desc.get_height());

    let expected_descriptor_bytes: Vec<u8> = vec![0x01, 0x08, 0x00];
    assert_eq!(expected_descriptor_bytes, desc.get_bytes());
}

#[test]
fn check_attributes_3() {
    let bytes: Vec<u8> = vec![0x01, 0x08, 0x00];
    let desc = QRLDescriptor::from_bytes(&bytes).unwrap();

    assert_ne!(*desc.get_hash_function(), HashFunction::SHA2_256);
    assert_eq!(*desc.get_hash_function(), HashFunction::Shake128);
    assert_eq!(*desc.get_signature_type(), SignatureType::XMSS);
    assert_eq!(*desc.get_addr_format_type(), AddrFormatType::SHA256_2X);
    assert_eq!(16, desc.get_height());

    let expected_descriptor_bytes = vec![0x01, 0x08, 0x00];
    assert_eq!(expected_descriptor_bytes, desc.get_bytes());
}
