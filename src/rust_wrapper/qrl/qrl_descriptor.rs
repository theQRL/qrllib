use super::qrl_address_format::AddrFormatType;
use crate::rust_wrapper::errors::QRLErrors;
use crate::rust_wrapper::xmss_alt::hash_functions::HashFunction;

#[derive(Clone, Copy, PartialEq)]
pub enum SignatureType {
    XMSS = 0,
}

pub struct QRLDescriptor {
    hash_function: HashFunction,
    signature_type: SignatureType,
    height: u8,
    addr_format_type: AddrFormatType,
}

impl QRLDescriptor {
    const SIZE: u8 = 3;

    pub fn new(
        hash_function: HashFunction,
        signature_type: SignatureType,
        height: u8,
        addr_format_type: AddrFormatType,
    ) -> QRLDescriptor {
        QRLDescriptor {
            hash_function,
            signature_type,
            height,
            addr_format_type,
        }
    }

    pub fn get_hash_function(&'_ self) -> &'_ HashFunction {
        return &self.hash_function;
    }

    pub fn get_signature_type(&'_ self) -> &'_ SignatureType {
        return &self.signature_type;
    }

    pub fn get_height(&'_ self) -> u8 {
        return self.height;
    }

    pub fn get_addr_format_type(&'_ self) -> &'_ AddrFormatType {
        return &self.addr_format_type;
    }

    pub fn from_bytes(bytes: &Vec<u8>) -> Result<Self, QRLErrors> {
        if bytes.len() != 3 {
            return Err(QRLErrors::InvalidArgument(
                "Descriptor size should be 3 bytes".to_string(),
            ));
        }

        let hash_function: HashFunction = match bytes[0] & 0x0F {
            0 => HashFunction::SHA2_256,
            1 => HashFunction::Shake128,
            2 => HashFunction::Shake256,
            _ => {
                return Err(QRLErrors::FailedConversion(
                    "Could not convert from u8 to HashFunction".to_string(),
                ))
            }
        };
        let signature_type: SignatureType = match (bytes[0] >> 4) & 0xF0 {
            0 => SignatureType::XMSS,
            _ => {
                return Err(QRLErrors::FailedConversion(
                    "Could not convert from u8 to SignatureType".to_string(),
                ))
            }
        };
        let height: u8 = (bytes[1] & 0x0F) << 1;
        let addr_format_type: AddrFormatType = match (bytes[1] & 0xF0) >> 4 {
            0 => AddrFormatType::SHA256_2X,
            _ => {
                return Err(QRLErrors::FailedConversion(
                    "Could not convert from u8 to AddrFormatType".to_string(),
                ))
            }
        };

        Ok(Self {
            hash_function,
            signature_type,
            height,
            addr_format_type,
        })
    }

    pub const fn get_size() -> u8 {
        Self::SIZE
    }

    pub fn from_extended_seed(extended_seed: &Vec<u8>) -> Result<Self, QRLErrors> {
        if extended_seed.len() != 51 {
            return Err(QRLErrors::InvalidArgument(
                "Extended seed should be 51 bytes".to_string(),
            ));
        }

        let bytes = extended_seed.get(0..Self::SIZE as usize).unwrap();
        return QRLDescriptor::from_bytes(&bytes.to_vec());
    }

    pub fn from_extended_pk(extended_pk: &Vec<u8>) -> Result<Self, QRLErrors> {
        if extended_pk.len() != 67 {
            return Err(QRLErrors::InvalidArgument(
                "Invalid extended_pk size. It should be 67 bytes".to_string(),
            ));
        }

        let bytes = extended_pk.get(0..Self::SIZE as usize).unwrap();
        return QRLDescriptor::from_bytes(&bytes.to_vec());
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        // descriptor
        //  0.. 3   hash function    [ SHA2-256, SHA3, .. ]
        //  4.. 7   signature scheme [ XMSS, XMSS^MT, .. ]
        //  8..11   params:  i.e. Height / 2
        // 12..15   params2: reserved
        // 16..23   params3: reserved

        let descr: Vec<u8> = vec![
            (((self.signature_type as u8) << 4) | ((self.hash_function as u8) & 0x0F)),
            (((self.addr_format_type as u8) << 4) | ((self.height >> 1) & 0x0F)),
            0,
        ];

        return descr;
    }
}
