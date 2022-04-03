use super::hashing::shake256;
use super::wordlist::WORDLIST;
use crate::rust_wrapper::errors::QRLError;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use std::mem::size_of;
pub const ADDRESS_HASH_SIZE: usize = 32;

pub fn bin2hstr(vec: &Vec<u8>, wrap: u32) -> String {
    let mut s = String::new();

    let mut count = 0;
    for val in vec {
        if wrap > 0 {
            count += 1;
            if count > wrap {
                s.push('\n');
                count = 1;
            }
        }
        s.extend(format!("{:02x}", val).chars());
    }
    s
}

pub fn str2bin(s: &String) -> Vec<u8> {
    s.as_bytes().to_vec()
}

pub fn binstr2hstr(s: &String, wrap: u32) -> String {
    bin2hstr(&str2bin(s), wrap)
}

fn get_hex_value(c: char) -> u8 {
    let tmp = c.to_lowercase().to_string().chars().next().unwrap();
    if tmp.is_digit(10) {
        tmp as u8 - b'0'
    } else {
        tmp as u8 - b'a' + 10
    }
}

pub fn hstr2bin(s: &String) -> Result<Vec<u8>, QRLError> {
    if s.len() % 2 != 0 {
        return Err(QRLError::InvalidArgument(
            "hex string is expected to have an even number of characters".to_owned(),
        ));
    }

    let mut result: Vec<u8> = Vec::new();
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
    Ok(result)
}

pub fn bin2mnemonic(vec: &Vec<u8>) -> Result<String, QRLError> {
    if vec.len() % 3 != 0 {
        return Err(QRLError::InvalidArgument(
            "byte count needs to be a multiple of 3".to_owned(),
        ));
    }
    let mut s = String::new();
    let separator = " ";
    for nibble in (0..vec.len() * 2).step_by(3) {
        let p = (nibble >> 1) as usize;
        let b1 = vec[p] as i32;
        let b2 = if p + 1 < vec.len() {
            vec[p + 1] as i32
        } else {
            0
        };
        let idx = if nibble % 2 == 0 {
            (b1 << 4) + (b2 >> 4)
        } else {
            ((b1 & 0x0F) << 8) + b2
        };
        if nibble != 0 {
            s.push_str(separator);
        }
        s.push_str(WORDLIST[idx as usize]);
    }
    Ok(s)
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

    let mut result: Vec<u8> = Vec::new();

    let mut current = 0;
    let mut buffering = 0;
    for word in mnemonic.split_whitespace() {
        let it = word_lookup.get(word);
        if it.is_none() {
            return Err(QRLError::InvalidArgument(format!(
                "invalid word: {} in the mnemonic",
                word
            )));
        }

        let value = it.unwrap();
        buffering += 3;
        current = (current << 12) + value;

        while buffering > 2 {
            let shift = 4 * (buffering - 2);
            let mask = (1 << shift) - 1;
            let tmp = current >> shift;
            buffering -= 2;
            current &= mask;
            result.push(tmp as u8);
        }
    }

    if buffering > 0 {
        result.push(current as u8 & 0xFF);
    }

    Ok(result)
}

pub fn get_random_seed(seed_size: u32, entropy: &String) -> Vec<u8> {
    let mut tmp: Vec<u8> = vec![0; seed_size as usize];
    OsRng.fill_bytes(&mut tmp);

    let tmpbytes = str2bin(entropy);
    tmp.extend(tmpbytes);
    return shake256(seed_size as usize, &tmp);
}

pub fn get_hash_chain_seed(seed: &Vec<u8>, seed_shift: u32, count: u32) -> Vec<Vec<u8>> {
    let mut result: Vec<Vec<u8>> = Vec::new();
    let mut tmp_seed: Vec<u8> = seed.clone();
    tmp_seed.resize(seed.len() + (size_of::<u32>() * 2), 0);

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
    result
}
