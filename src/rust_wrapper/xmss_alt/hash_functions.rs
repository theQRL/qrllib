#[derive(Clone, Copy)]
#[repr(u8)]
pub enum HashFunction {
    SHA2_256 = 0,
    Shake128 = 1,
    Shake256 = 2,
}
