pub fn to_byte(out: &mut [u8], mut input: u64, bytes: u32) {
    for i in (0..=(bytes - 1) as usize).rev() {
        out[i] = (input & 0xff) as u8;
        input = input >> 8;
    }
}
