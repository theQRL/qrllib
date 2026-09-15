use super::hashing::shake256;
use super::wordlist::WORDLIST;
use crate::rust_wrapper::errors::QRLError;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::mem::size_of;
use zeroize::Zeroizing;
pub const ADDRESS_HASH_SIZE: usize = 32;

pub fn bin2hstr(vec: &Vec<u8>, wrap: u32) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let wrap = usize::try_from(wrap).unwrap_or(usize::MAX);
    let line_breaks = if wrap == 0 || vec.is_empty() {
        0
    } else {
        (vec.len() - 1) / wrap
    };
    let output_size = vec
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(line_breaks))
        .expect("hex output is too large");
    let mut output = Zeroizing::new(String::with_capacity(output_size));

    for (index, value) in vec.iter().enumerate() {
        if wrap != 0 && index != 0 && index % wrap == 0 {
            output.push('\n');
        }
        output.push(HEX[(value >> 4) as usize] as char);
        output.push(HEX[(value & 0x0f) as usize] as char);
    }

    std::mem::take(&mut *output)
}

pub fn str2bin(s: &String) -> Vec<u8> {
    s.as_bytes().to_vec()
}

pub fn binstr2hstr(s: &String, wrap: u32) -> String {
    let bytes = Zeroizing::new(str2bin(s));
    bin2hstr(&bytes, wrap)
}

fn get_hex_value(c: char) -> u8 {
    c.to_digit(16).expect("validated hexadecimal digit") as u8
}

pub fn hstr2bin(s: &String) -> Result<Vec<u8>, QRLError> {
    if s.len() % 2 != 0 {
        return Err(QRLError::InvalidArgument(
            "hex string is expected to have an even number of characters".to_owned(),
        ));
    }

    let mut result = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    let mut s_iter = s.chars().peekable();
    while s_iter.peek().is_some() {
        let c1_option = s_iter.next();
        let c2_option = s_iter.next();
        if c1_option.is_none() || c2_option.is_none() {
            return Err(QRLError::InvalidArgument(
                "invalid hex digits in the string".to_owned(),
            ));
        }
        let c1 = c1_option.unwrap();
        let c2 = c2_option.unwrap();
        if !c1.is_digit(16) || !c2.is_digit(16) {
            return Err(QRLError::InvalidArgument(
                "invalid hex digits in the string".to_owned(),
            ));
        }

        let v = (get_hex_value(c1) << 4) + get_hex_value(c2);
        result.push(v);
    }
    Ok(std::mem::take(&mut *result))
}

pub fn bin2mnemonic(vec: &Vec<u8>) -> Result<String, QRLError> {
    if vec.len() % 3 != 0 {
        return Err(QRLError::InvalidArgument(
            "byte count needs to be a multiple of 3".to_owned(),
        ));
    }
    let word_count = (vec.len() / 3)
        .checked_mul(2)
        .ok_or_else(|| QRLError::InvalidArgument("mnemonic output is too large".to_owned()))?;
    let mut output_size = word_count.saturating_sub(1);
    for bytes in vec.chunks_exact(3) {
        let first = ((bytes[0] as usize) << 4) | ((bytes[1] as usize) >> 4);
        let second = (((bytes[1] as usize) & 0x0f) << 8) | bytes[2] as usize;
        output_size = output_size
            .checked_add(WORDLIST[first].len())
            .and_then(|size| size.checked_add(WORDLIST[second].len()))
            .ok_or_else(|| QRLError::InvalidArgument("mnemonic output is too large".to_owned()))?;
    }

    let mut output = Zeroizing::new(String::with_capacity(output_size));
    for (group, bytes) in vec.chunks_exact(3).enumerate() {
        let first = ((bytes[0] as usize) << 4) | ((bytes[1] as usize) >> 4);
        let second = (((bytes[1] as usize) & 0x0f) << 8) | bytes[2] as usize;
        if group != 0 {
            output.push(' ');
        }
        output.push_str(WORDLIST[first]);
        output.push(' ');
        output.push_str(WORDLIST[second]);
    }
    Ok(std::mem::take(&mut *output))
}

pub fn mnemonic2bin(mnemonic: &String) -> Result<Vec<u8>, QRLError> {
    let word_count = mnemonic.split_whitespace().count();
    if word_count % 2 != 0 {
        return Err(QRLError::InvalidArgument(format!(
            "word count = {} must be even",
            word_count
        )));
    }

    let mut word_lookup: HashMap<String, u32> = HashMap::new();
    let mut count = 0;
    for word in WORDLIST {
        word_lookup.insert(word.to_string(), count);
        count += 1;
    }

    let result_capacity = word_count
        .checked_mul(3)
        .map(|bytes| bytes / 2)
        .ok_or_else(|| QRLError::InvalidArgument("mnemonic input is too large".to_owned()))?;
    let mut result = Zeroizing::new(Vec::with_capacity(result_capacity));

    let mut current = Zeroizing::new(0_u32);
    let mut buffering = 0;
    for word in mnemonic.split_whitespace() {
        let it = word_lookup.get(word);
        if it.is_none() {
            return Err(QRLError::InvalidArgument(
                "invalid word in mnemonic".to_owned(),
            ));
        }

        let value = it.unwrap();
        buffering += 3;
        *current = (*current << 12) + *value;

        while buffering > 2 {
            let shift = 4 * (buffering - 2);
            let mask = (1 << shift) - 1;
            let tmp = Zeroizing::new(*current >> shift);
            buffering -= 2;
            *current &= mask;
            result.push(*tmp as u8);
        }
    }

    if buffering > 0 {
        result.push(*current as u8 & 0xFF);
    }

    Ok(std::mem::take(&mut *result))
}

pub fn get_random_seed(seed_size: u32, entropy: &String) -> Vec<u8> {
    let tmpbytes = Zeroizing::new(str2bin(entropy));
    let random_bytes = seed_size as usize;
    let tmp_capacity = random_bytes
        .checked_add(tmpbytes.len())
        .expect("random seed input is too large");
    let mut tmp = Zeroizing::new(Vec::with_capacity(tmp_capacity));
    tmp.resize(random_bytes, 0);
    OsRng.fill_bytes(&mut tmp);

    tmp.extend_from_slice(&tmpbytes);
    shake256(seed_size as usize, &tmp)
}

pub fn get_hash_chain_seed(seed: &Vec<u8>, seed_shift: u32, count: u32) -> Vec<Vec<u8>> {
    let mut result = Zeroizing::new(Vec::<Vec<u8>>::new());
    let tmp_seed_size = seed
        .len()
        .checked_add(size_of::<u32>() * 2)
        .expect("hash-chain seed is too large");
    let mut tmp_seed = Zeroizing::new(Vec::with_capacity(tmp_seed_size));
    tmp_seed.extend_from_slice(seed);
    tmp_seed.resize(tmp_seed_size, 0);

    let mut p = seed.len();
    for j in 0..size_of::<u32>() {
        tmp_seed[p + j] = (seed_shift >> (8 * j)) as u8 & 0xFF;
    }

    p += size_of::<u32>();
    for i in 0..count {
        for j in 0..size_of::<u32>() {
            tmp_seed[p + j] = (i >> (8 * j)) as u8 & 0xFF;
        }
        result.push(shake256(32, &tmp_seed));
    }
    std::mem::take(&mut *result)
}
