#[derive(Debug)]
pub enum QRLError {
    InvalidArgument(String),
    FailedConversion(String),
}
