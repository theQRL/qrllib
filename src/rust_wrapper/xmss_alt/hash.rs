use super::fips202::{shake128, shake256};
use super::hash_address::set_key_and_mask;
use super::hash_functions::HashFunction;
use super::xmss_common::to_byte;
use crate::rust_wrapper::shasha::shasha::sha2_256;
use zeroize::Zeroizing;

pub fn u32_slice_to_bytes(input: &[u32], num_bytes: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 * input.len());

    for value in input {
        bytes.extend(&value.to_be_bytes());
    }

    bytes[0..num_bytes].to_vec()
}

pub fn addr_to_byte<'a>(bytes: &'a mut [u8], addr: &[u32; 8]) -> &'a [u8] {
    if cfg!(target_endian = "little") {
        let bytes_length = bytes.len();
        for i in 0..8 {
            to_byte(&mut bytes[i * 4..bytes_length], addr[i] as u64, 4);
        }
        return bytes;
    } else {
        bytes.copy_from_slice(&u32_slice_to_bytes(addr, 32));
        return bytes;
    }
}

pub fn core_hash(
    hash_func: &HashFunction,
    out: &mut [u8],
    type_t: u32,
    key: &[u8],
    keylen: u32,
    input: &[u8],
    inlen: u32,
    n: u32,
) -> u32 {
    if !matches!(n, 32 | 64)
        || key.len() < keylen as usize
        || input.len() < inlen as usize
        || out.len() < n as usize
    {
        out.fill(0);
        return 1;
    }
    let Some(buf_size) = (inlen as usize)
        .checked_add(n as usize)
        .and_then(|size| size.checked_add(keylen as usize))
    else {
        out.fill(0);
        return 1;
    };
    let mut buf = Zeroizing::new(vec![0; buf_size]);

    // Input is (toByte(X, 32) || KEY || M)

    // set toByte
    to_byte(&mut buf, type_t.into(), n);

    let key_start = n as usize;
    let input_start = key_start + keylen as usize;
    buf[key_start..input_start].copy_from_slice(&key[..keylen as usize]);
    buf[input_start..buf_size].copy_from_slice(&input[..inlen as usize]);

    match hash_func {
        HashFunction::Shake128 if n == 32 => {
            shake128(out, 32, &buf, buf_size as u64);
            0
        }
        HashFunction::Shake128 if n == 64 => {
            shake128(out, 64, &buf, buf_size as u64);
            0
        }
        HashFunction::Shake256 if n == 32 => {
            shake256(out, 32, &buf, buf_size as u64);
            0
        }
        HashFunction::Shake256 if n == 64 => {
            shake256(out, 64, &buf, buf_size as u64);
            0
        }
        HashFunction::SHA2_256 if n == 32 => {
            let buf_sha2_256 = Zeroizing::new(sha2_256(&buf));
            out.get_mut(0..buf_sha2_256.len())
                .unwrap()
                .copy_from_slice(buf_sha2_256.as_slice());
            0
        }
        _ => {
            out[..n as usize].fill(0);
            1
        }
    }
}

/**
 * Implements PRF
 */
pub fn prf(hash_func: &HashFunction, out: &mut [u8], input: &[u8], key: &[u8], keylen: u32) -> u32 {
    return core_hash(hash_func, out, 3, key, keylen, input, 32, keylen);
}

/*
 * Implemts H_msg
 */
pub fn h_msg(
    hash_func: &HashFunction,
    out: &mut [u8],
    input: &[u8],
    inlen: u64,
    key: &[u8],
    keylen: u32,
    n: u32,
) -> u32 {
    if n.checked_mul(3) != Some(keylen) || inlen > u32::MAX as u64 || inlen as usize != input.len()
    {
        eprintln!(
            "H_msg takes 3n-bit keys, we got n={} but a keylength of {}.\n",
            n, keylen
        );
        out.fill(0);
        return 1;
    }
    return core_hash(hash_func, out, 2, key, keylen, input, inlen as u32, n);
}

/**
 * We assume the left half is in input[0]...input[n-1]
 */
pub fn hash_h(
    hash_func: &HashFunction,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
    n: u32,
) -> u32 {
    let Some(input_length) = (n as usize).checked_mul(2) else {
        out.fill(0);
        return 1;
    };
    if !matches!(n, 32 | 64)
        || out.len() < n as usize
        || input.len() < input_length
        || pub_seed.len() < n as usize
    {
        out.fill(0);
        return 1;
    }
    let mut buf: Vec<u8> = vec![0; 2 * n as usize];
    let mut key: Vec<u8> = vec![0; n as usize];
    let mut bitmask: Vec<u8> = vec![0; 2 * n as usize];
    let mut byte_addr: Vec<u8> = vec![0; 32];

    set_key_and_mask(addr, 0);
    addr_to_byte(&mut byte_addr, addr);
    prf(hash_func, &mut key, &byte_addr, pub_seed, n);
    // Use MSB order
    set_key_and_mask(addr, 1);
    addr_to_byte(&mut byte_addr, addr);
    prf(hash_func, &mut bitmask, &byte_addr, pub_seed, n);
    set_key_and_mask(addr, 2);
    addr_to_byte(&mut byte_addr, addr);
    let out_length = bitmask.len();
    let bitmask_out = bitmask.get_mut(n as usize..out_length).unwrap();
    prf(hash_func, bitmask_out, &byte_addr, pub_seed, n);
    for i in 0..(2 * n as usize) {
        buf[i] = input[i] ^ bitmask[i];
    }
    return core_hash(hash_func, out, 1, &key, n, &buf, 2 * n, n);
}

pub fn hash_f(
    hash_func: &HashFunction,
    out: &mut [u8],
    input: &[u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
    n: u32,
) -> u32 {
    if !matches!(n, 32 | 64)
        || out.len() < n as usize
        || input.len() < n as usize
        || pub_seed.len() < n as usize
    {
        out.fill(0);
        return 1;
    }
    let mut buf = Zeroizing::new(vec![0; n as usize]);
    let mut key: Vec<u8> = vec![0; n as usize];
    let mut bitmask: Vec<u8> = vec![0; n as usize];
    let mut byte_addr: Vec<u8> = vec![0; 32];

    set_key_and_mask(addr, 0);
    addr_to_byte(&mut byte_addr, addr);
    prf(&hash_func, &mut key, &byte_addr, pub_seed, n);

    set_key_and_mask(addr, 1);
    addr_to_byte(&mut byte_addr, addr);
    prf(&hash_func, &mut bitmask, &byte_addr, pub_seed, n);

    for i in 0..n as usize {
        buf[i] = input[i] ^ bitmask[i];
    }
    return core_hash(&hash_func, out, 0, &key, n, &buf, n, n);
}
