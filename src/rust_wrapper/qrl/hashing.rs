use crate::rust_wrapper::xmss_alt::fips202;
use crate::rust_wrapper::{errors::QRLError, shasha::shasha};

pub fn shake128(hash_size: usize, input: &Vec<u8>) -> Vec<u8> {
    let mut hashed_output = vec![0; hash_size];
    fips202::shake128(&mut hashed_output, hash_size, &input, input.len() as u64);
    hashed_output
}

pub fn shake256(hash_size: usize, input: &Vec<u8>) -> Vec<u8> {
    let mut hashed_output = vec![0; hash_size];
    fips202::shake256(&mut hashed_output, hash_size, &input, input.len() as u64);
    hashed_output
}

pub fn sha2_256(input: &Vec<u8>) -> Vec<u8> {
    shasha::sha2_256(&input)
}

pub fn sha2_256_n(input: &Vec<u8>, count: usize) -> Result<Vec<u8>, QRLError> {
    if count == 0 {
        return Err(QRLError::InvalidArgument(
            "Invalid count. It should be > 0".to_owned(),
        ));
    }

    let mut hashed_output = shasha::sha2_256(input);
    for _ in 1..count {
        hashed_output = shasha::sha2_256(&hashed_output);
    }

    return Ok(hashed_output);
}
