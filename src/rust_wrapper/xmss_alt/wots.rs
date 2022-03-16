use super::hash::{hash_f, prf};
use super::hash_address::{set_chain_adrs, set_hash_adrs};
use super::hash_functions::HashFunction;
use super::xmss_common::to_byte;
use std::cmp::min;

macro_rules! log2 {
    ($val:expr, $type:ty) => {
        ($val as f32).log2() as $type
    };
}

/**
 * WOTS parameter set
 *
 * Meaning as defined in draft-irtf-cfrg-xmss-hash-based-signatures-02
 */
// FIXME: Get rid of this
pub struct WOTSParams {
    pub len_1: u32,
    pub len_2: u32,
    pub len: u32,
    pub n: u32,
    pub w: u32,
    pub log_w: u32,
    pub keysize: u32,
}

impl WOTSParams {
    /**
     * Set the WOTS parameters,
     * only n and w are required as inputs,
     * len, len_1, and len_2 are computed from those.
     *
     * Assumes w is a power of 2
     */
    pub fn new(n: u32, w: u32) -> Self {
        let log_w = log2!(w, u32);
        let len_1 = ((8 * n) as f32 / (log_w as f32)).ceil() as u32;
        let len_2 = (log2!(len_1 * (w - 1), f32) / log_w as f32).floor() as u32 + 1;
        let len = len_1 + len_2;
        let keysize = len * n;
        WOTSParams {
            n,
            w,
            log_w,
            len_1,
            len_2,
            len,
            keysize,
        }
    }
}

/**
 * Helper method for pseudorandom key generation
 * Expands an n-byte array into a len*n byte array
 * this is done using PRF
 */
fn expand_seed(hash_func: &HashFunction, outseeds: &mut [u8], inseed: &[u8], n: u32, len: u32) {
    let mut ctr = vec![0 as u8; 32];
    let outseeds_length = outseeds.len();
    for i in 0..len {
        to_byte(ctr.as_mut_slice(), i.into(), 32);
        prf(
            &hash_func,
            &mut outseeds.get_mut((i * n) as usize..outseeds_length).unwrap(),
            ctr.as_mut_slice(),
            inseed,
            n,
        );
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays
 *
 * interpretes in as start-th value of the chain
 * addr has to contain the address of the chain
 */
fn gen_chain(
    hash_func: &HashFunction,
    out: &mut [u8],
    input: &[u8],
    start: u32,
    steps: u32,
    params: &WOTSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    for j in 0..params.n as usize {
        out[j] = input[j];
    }

    for i in start..(min(start + steps, params.w)) {
        set_hash_adrs(addr, i);
        let mut input = vec![0; out.len()];
        input.copy_from_slice(out);
        hash_f(hash_func, out, &input, pub_seed, addr, params.n);
    }
}

/**
 * base_w algorithm as described in draft.
 */
fn base_w(output: &mut [i32], out_len: usize, input: &[u8], params: &WOTSParams) {
    let mut in_ = 0;
    let mut out = 0;
    let mut total = 0;
    let mut bits = 0;

    for _consumed in 0..out_len {
        if bits == 0 {
            total = input[in_];
            in_ += 1;
            bits += 8;
        }
        bits -= params.log_w;
        output[out] = ((total >> bits) as u32 & (params.w - 1)) as i32;
        out += 1;
    }
}

/**
 * WOTS key generation. Takes a 32byte seed for the secret key, expands it to a full WOTS secret key and computes the corresponding public key.
 * For this it takes the seed pub_seed which is used to generate bitmasks and hash keys and the address of this WOTS key pair addr
 *
 * params, must have been initialized before using wots_set params for params ! This is not done in this function
 *
 * Places the computed public key at address pk.
 */
pub fn wots_pkgen(
    hash_func: &HashFunction,
    pk: &mut [u8],
    sk: &[u8],
    params: &WOTSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    expand_seed(hash_func, pk, sk, params.n, params.len);
    let pk_len = pk.len();
    let mut pk_input = vec![0; pk_len];
    pk_input.copy_from_slice(pk);
    for i in 0..params.len {
        set_chain_adrs(addr, i);
        gen_chain(
            hash_func,
            pk.get_mut((i * params.n) as usize..pk_len as usize)
                .unwrap(),
            pk_input
                .get((i * params.n) as usize..pk_len as usize)
                .unwrap(),
            0,
            params.w - 1,
            params,
            pub_seed,
            addr,
        );
    }
}

pub fn wots_sign(
    hash_func: &HashFunction,
    sig: &mut [u8],
    msg: &[u8],
    sk: &[u8],
    params: &WOTSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let mut basew: Vec<i32> = vec![0; params.len as usize];
    let mut csum = 0;

    base_w(&mut basew, params.len_1.try_into().unwrap(), msg, params);

    for i in 0..params.len_1 as usize {
        csum += params.w as i32 - 1 - basew[i];
    }

    csum = csum << (8 - ((params.len_2 * params.log_w) % 8));

    let len_2_bytes = ((params.len_2 * params.log_w) + 7) / 8;

    let mut csum_bytes: Vec<u8> = vec![0; len_2_bytes as usize];
    to_byte(&mut csum_bytes, csum.try_into().unwrap(), len_2_bytes);

    let mut csum_basew: Vec<i32> = vec![0; params.len_2 as usize];

    base_w(&mut csum_basew, params.len_2 as usize, &csum_bytes, params);

    for i in 0..params.len_2 {
        basew[(params.len_1 + i) as usize] = csum_basew[i as usize];
    }

    expand_seed(hash_func, sig, sk, params.n, params.len);

    for i in 0..params.len {
        set_chain_adrs(addr, i);
        let sig_length = sig.len();
        let sig_output_segment = sig.get_mut((i * params.n) as usize..sig_length).unwrap();
        let mut sig_input_segment: Vec<u8> = vec![0; sig_output_segment.len()];
        sig_input_segment.copy_from_slice(sig_output_segment);
        gen_chain(
            hash_func,
            sig_output_segment,
            &sig_input_segment,
            0,
            basew[i as usize].try_into().unwrap(),
            params,
            pub_seed,
            addr,
        );
    }
}

pub fn wots_pk_from_sig(
    hash_func: &HashFunction,
    pk: &mut [u8],
    sig: &[u8],
    msg: &[u8],
    wots_params: &WOTSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let XMSS_WOTS_LEN = wots_params.len as usize;
    let XMSS_WOTS_LEN1 = wots_params.len_1 as usize;
    let XMSS_WOTS_LEN2 = wots_params.len_2 as usize;
    let XMSS_WOTS_LOG_W = wots_params.log_w as usize;
    let XMSS_WOTS_W = wots_params.w;
    let XMSS_N = wots_params.n;

    let mut basew: Vec<i32> = vec![0; XMSS_WOTS_LEN];
    let mut csum = 0;
    let mut csum_bytes: Vec<u8> = vec![0; ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) + 7) / 8];
    let mut csum_basew: Vec<i32> = vec![0; XMSS_WOTS_LEN2];

    base_w(&mut basew, XMSS_WOTS_LEN1, msg, wots_params);

    for i in 0..XMSS_WOTS_LEN1 {
        csum += XMSS_WOTS_W - 1 - basew[i] as u32;
    }

    csum = csum << (8 - ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) % 8));

    to_byte(
        &mut csum_bytes,
        csum.into(),
        ((XMSS_WOTS_LEN2 * XMSS_WOTS_LOG_W) as u32 + 7) / 8,
    );
    base_w(&mut csum_basew, XMSS_WOTS_LEN2, &csum_bytes, wots_params);

    for i in 0..XMSS_WOTS_LEN2 {
        basew[XMSS_WOTS_LEN1 + i] = csum_basew[i];
    }
    for i in 0..XMSS_WOTS_LEN {
        set_chain_adrs(addr, i.try_into().unwrap());
        let out = pk.get_mut(i * XMSS_N as usize..pk.len()).unwrap();
        let input = sig.get(i * XMSS_N as usize..sig.len()).unwrap();
        gen_chain(
            hash_func,
            out,
            input,
            basew[i].try_into().unwrap(),
            XMSS_WOTS_W - 1 - basew[i] as u32,
            wots_params,
            pub_seed,
            addr,
        );
    }
}
