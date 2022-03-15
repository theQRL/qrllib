use super::misc::ADDRESS_HASH_SIZE;
use super::qrl_address_format::AddrFormatType;
use super::qrl_descriptor::QRLDescriptor;
use crate::rust_wrapper::{errors::QRLErrors, shasha::shasha::sha2_256};

pub fn get_address(extended_pk: &Vec<u8>) -> Result<Vec<u8>, QRLErrors> {
    let descr = QRLDescriptor::from_extended_pk(extended_pk)?;

    if *descr.get_addr_format_type() != AddrFormatType::SHA256_2X {
        return Err(QRLErrors::InvalidArgument(
            "Address format type not supported".to_owned(),
        ));
    }

    let descr_bytes = descr.get_bytes();
    let mut address = descr_bytes;

    let mut hashed_key: Vec<u8> = sha2_256(extended_pk);

    #[cfg(test)]
    assert_eq!(hashed_key.len(), ADDRESS_HASH_SIZE);

    address.append(&mut hashed_key);

    let hashed_key2: Vec<u8> = sha2_256(&address);

    #[cfg(test)]
    assert_eq!(hashed_key2.len(), ADDRESS_HASH_SIZE);

    let hashed_key2_len = hashed_key2.len();
    let mut hashed_key2_segment = hashed_key2[hashed_key2_len - 4..hashed_key2_len].to_vec();
    address.append(&mut hashed_key2_segment);

    return Ok(address);
}

pub fn address_is_valid(address: &Vec<u8>) -> bool {
    if address.len() != (QRLDescriptor::get_size() as usize + ADDRESS_HASH_SIZE + 4) {
        return false;
    }

    let descr_result =
        QRLDescriptor::from_bytes(&address[0..QRLDescriptor::get_size() as usize].to_vec());

    if let Ok(descr) = descr_result {
        if *descr.get_addr_format_type() != AddrFormatType::SHA256_2X {
            return false;
        }

        let address_segment =
            address[0..QRLDescriptor::get_size() as usize + ADDRESS_HASH_SIZE].to_vec();
        let hashed_key2: Vec<u8> = sha2_256(&address_segment);

        return address[35] == hashed_key2[28]
            && address[36] == hashed_key2[29]
            && address[37] == hashed_key2[30]
            && address[38] == hashed_key2[31];
    } else {
        return false;
    }
}
