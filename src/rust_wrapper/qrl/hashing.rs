use crate::rust_wrapper::{errors::QRLErrors, shasha::shasha::sha2_256};

fn sha2_256_n(input: Vec<u8>, count: usize) -> Result<Vec<u8>, QRLErrors> {
    if count == 0 {
        return Err(QRLErrors::InvalidArgument(
            "Invalid count. It should be > 0".to_owned(),
        ));
    }

    let mut hashed_output = sha2_256(&input);
    for _ in 1..count {
        hashed_output = sha2_256(&hashed_output);
    }

    return Ok(hashed_output);
}
