#[derive(Debug)]
pub enum QRLErrors {
    InvalidArgument(String),
    FailedConversion(String),
}
