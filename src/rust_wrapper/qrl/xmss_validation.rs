use crate::rust_wrapper::errors::QRLError;

pub(crate) const SEED_SIZE: usize = 48;
pub(crate) const EXTENDED_SEED_SIZE: usize = 51;
pub(crate) const SECRET_KEY_SIZE: usize = 132;
pub(crate) const EXTENDED_PUBLIC_KEY_SIZE: usize = 67;
pub(crate) const MIN_HEIGHT: u8 = 4;
pub(crate) const MAX_HEIGHT: u8 = 30;
pub(crate) const BDS_K: u32 = 2;
pub(crate) const N: u32 = 32;

pub(crate) fn validate_height(height: u8) -> Result<(), QRLError> {
    if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&height) || height % 2 != 0 {
        return Err(QRLError::InvalidArgument(
            "XMSS height must be even and between 4 and 30".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_wots(w: u32) -> Result<(), QRLError> {
    if !matches!(w, 2 | 4 | 16 | 256) {
        return Err(QRLError::InvalidArgument(
            "Unsupported XMSS WOTS parameter".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn signature_count(height: u8) -> Result<u32, QRLError> {
    validate_height(height)?;
    1_u32.checked_shl(height.into()).ok_or_else(|| {
        QRLError::InvalidArgument("XMSS height is unsafe for index arithmetic".to_owned())
    })
}
