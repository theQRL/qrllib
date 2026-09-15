use super::hash::{h_msg, hash_h};
use super::hash_address::{set_ltree_adrs, set_ots_adrs, set_type};
use super::{
    hash_address::{set_tree_height, set_tree_index},
    hash_functions::HashFunction,
    wots::{wots_pk_from_sig, WOTSParams},
};
use crate::rust_wrapper::errors::QRLError;
use crate::rust_wrapper::qrl::xmss_validation::{
    signature_count, validate_height, validate_wots, BDS_K, N,
};

#[derive(Default)]
pub struct XMSSParams {
    pub wots_par: WOTSParams,
    pub n: u32,
    pub h: u32,
    pub k: u32,
}

impl XMSSParams {
    /**
     * Initialize xmss params struct
     * parameter names are the same as in the draft
     */
    pub fn new(n: u32, h: u32, w: u32, k: u32) -> Result<Self, QRLError> {
        if n != N {
            return Err(QRLError::InvalidArgument(
                "Unsupported XMSS hash size".to_owned(),
            ));
        }
        let height = u8::try_from(h)
            .map_err(|_| QRLError::InvalidArgument("XMSS height is out of range".to_owned()))?;
        validate_height(height)?;
        validate_wots(w)?;
        if k != BDS_K || k >= h || (h - k) % 2 != 0 {
            return Err(QRLError::InvalidArgument(
                "For BDS traversal, H - K must be even, with H > K >= 2!".to_owned(),
            ));
        }
        let wots_par = WOTSParams::new(n, w);
        Ok(XMSSParams { wots_par, n, h, k })
    }

    pub(crate) fn validate(&self) -> Result<(), QRLError> {
        let height = u8::try_from(self.h)
            .map_err(|_| QRLError::InvalidArgument("XMSS height is out of range".to_owned()))?;
        validate_height(height)?;
        validate_wots(self.wots_par.w)?;
        if self.n != N || self.k != BDS_K || self.k >= self.h || (self.h - self.k) % 2 != 0 {
            return Err(QRLError::InvalidArgument(
                "Invalid XMSS parameter state".to_owned(),
            ));
        }
        let expected = WOTSParams::new(self.n, self.wots_par.w);
        if self.wots_par.n != expected.n
            || self.wots_par.log_w != expected.log_w
            || self.wots_par.len_1 != expected.len_1
            || self.wots_par.len_2 != expected.len_2
            || self.wots_par.len != expected.len
            || self.wots_par.keysize != expected.keysize
        {
            return Err(QRLError::InvalidArgument(
                "Invalid XMSS WOTS parameter state".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn to_byte(out: &mut [u8], mut input: u64, bytes: u32) {
    for i in (0..=(bytes - 1) as usize).rev() {
        out[i] = (input & 0xff) as u8;
        input = input >> 8;
    }
}

pub fn l_tree(
    hash_func: &HashFunction,
    params: &WOTSParams,
    leaf: &mut [u8],
    wots_pk: &mut [u8],
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let mut l = params.len;
    let n = params.n;
    let mut height = 0;

    set_tree_height(addr, height);

    while l > 1 {
        let bound = l >> 1;
        for i in 0..bound {
            set_tree_index(addr, i);
            let wots_pk_length = wots_pk.len();
            let mut input = Vec::new();
            input.extend(wots_pk.get((i * 2 * n) as usize..wots_pk_length).unwrap());
            let out = wots_pk.get_mut((i * n) as usize..wots_pk_length).unwrap();
            hash_h(hash_func, out, &input, pub_seed, addr, n);
        }
        if (l & 1) != 0 {
            let dest_start = ((l >> 1) * n) as usize;
            let src_start = ((l - 1) * n) as usize;
            wots_pk.copy_within(src_start..(src_start + n as usize), dest_start);
            l = (l >> 1) + 1;
        } else {
            l = l >> 1;
        }
        height += 1;
        set_tree_height(addr, height);
    }
    let leaf_dest = leaf.get_mut(0..n as usize).unwrap();
    let wots_pk_src = wots_pk.get(0..n as usize).unwrap();
    leaf_dest.clone_from_slice(wots_pk_src);
}

/**
 * Computes a root node given a leaf and an authapth
 */
fn validate_authpath(
    hash_func: &HashFunction,
    root: &mut [u8],
    leaf: &[u8],
    mut leafidx: u64,
    mut authpath: &[u8],
    n: u32,
    h: u32,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let mut buffer: Vec<u8> = vec![0; 2 * n as usize];

    // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
    // Otherwise, it is the other way around
    if (leafidx & 1) != 0 {
        for j in 0..n as usize {
            buffer[n as usize + j] = leaf[j];
        }
        for j in 0..n as usize {
            buffer[j] = authpath[j];
        }
    } else {
        for j in 0..n as usize {
            buffer[j] = leaf[j];
        }
        for j in 0..n as usize {
            buffer[n as usize + j] = authpath[j];
        }
    }
    authpath = authpath.get(n as usize..authpath.len()).unwrap();

    for i in 0..(h - 1) {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx as u32);
        if (leafidx & 1) != 0 {
            let buffer_len = buffer.len();
            let input_slice = buffer.clone();
            hash_h(
                hash_func,
                buffer.get_mut(n as usize..buffer_len).unwrap(),
                &input_slice,
                pub_seed,
                addr,
                n,
            );
            for j in 0..n as usize {
                buffer[j] = authpath[j];
            }
        } else {
            let input_slice = buffer.clone();
            hash_h(hash_func, &mut buffer, &input_slice, pub_seed, addr, n);
            for j in 0..n as usize {
                buffer[j + n as usize] = authpath[j];
            }
        }
        authpath = authpath.get(n as usize..authpath.len()).unwrap();
    }
    set_tree_height(addr, h - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx as u32);
    hash_h(hash_func, root, &buffer, pub_seed, addr, n);
}

/**
 * Verifies a given message signature pair under a given public key.
 */
pub fn xmss_verify_sig(
    hash_func: &HashFunction,
    wotsParams: &WOTSParams,
    msg: &mut [u8],
    msglen: usize,
    mut sig_msg: &[u8],
    pk: &[u8],
    h: u8,
) -> i32 {
    if validate_height(h).is_err() || validate_wots(wotsParams.w).is_err() {
        return -1;
    }
    let expected_wots = WOTSParams::new(N, wotsParams.w);
    if wotsParams.n != expected_wots.n
        || wotsParams.w != expected_wots.w
        || wotsParams.log_w != expected_wots.log_w
        || wotsParams.len != expected_wots.len
        || wotsParams.len_1 != expected_wots.len_1
        || wotsParams.len_2 != expected_wots.len_2
        || wotsParams.keysize != expected_wots.keysize
        || pk.len() != (2 * N) as usize
        || msglen != msg.len()
    {
        return -1;
    }
    let expected_signature_size = match 4_u32
        .checked_add(N)
        .and_then(|size| size.checked_add(wotsParams.keysize))
        .and_then(|size| size.checked_add((h as u32).checked_mul(N)?))
    {
        Some(size) => size as usize,
        None => return -1,
    };
    if sig_msg.len() != expected_signature_size {
        return -1;
    }

    let n = wotsParams.n;
    let mut sig_msg_len = expected_signature_size as u64;

    let mut wots_pk: Vec<u8> = vec![0; wotsParams.keysize as usize];
    let mut pkhash: Vec<u8> = vec![0; n.try_into().unwrap()];
    let mut root: Vec<u8> = vec![0; n.try_into().unwrap()];
    let mut msg_h: Vec<u8> = vec![0; n.try_into().unwrap()];
    let mut hash_key: Vec<u8> = vec![0; (n * 3) as usize];

    let mut pub_seed: Vec<u8> = vec![0; n.try_into().unwrap()];
    pub_seed.copy_from_slice(pk.get(n as usize..2 * n as usize).unwrap());

    // Init addresses
    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];

    set_type(ots_addr, 0);
    set_type(ltree_addr, 1);
    set_type(node_addr, 2);

    // Extract index
    let idx = ((sig_msg[0] as u32) << 24)
        | ((sig_msg[1] as u32) << 16)
        | ((sig_msg[2] as u32) << 8)
        | sig_msg[3] as u32;
    let signature_limit = match signature_count(h) {
        Ok(limit) => limit,
        Err(_) => return -1,
    };
    if idx >= signature_limit {
        return -1;
    }

    // printf("verify:: idx = %lu\n", idx);

    // Generate hash key (R || root || idx)
    hash_key[0..n as usize].copy_from_slice(sig_msg.get(4..(4 + n) as usize).unwrap());
    let hash_key_len = hash_key.len();
    let hash_key_segment = hash_key.get_mut(n as usize..hash_key_len).unwrap();
    hash_key_segment[0..n as usize].copy_from_slice(pk.get(0..n as usize).unwrap());
    let to_byte_out = hash_key.get_mut(2 * n as usize..hash_key_len).unwrap();
    to_byte(to_byte_out, idx.into(), n);

    sig_msg = sig_msg.get(n as usize + 4..sig_msg.len()).unwrap();
    sig_msg_len -= n as u64 + 4;

    // hash message
    let Ok(message_length) = u64::try_from(msglen) else {
        return -1;
    };
    if h_msg(
        hash_func,
        &mut msg_h,
        msg,
        message_length,
        &hash_key,
        3 * n,
        n,
    ) != 0
    {
        return -1;
    }
    //-----------------------
    // Verify signature
    //-----------------------

    // Prepare Address
    set_ots_adrs(ots_addr, idx);
    // Check WOTS signature
    wots_pk_from_sig(
        hash_func,
        &mut wots_pk,
        sig_msg,
        &msg_h,
        wotsParams,
        &pub_seed,
        ots_addr,
    );

    sig_msg = sig_msg
        .get(wotsParams.keysize as usize..sig_msg.len())
        .unwrap();
    sig_msg_len -= wotsParams.keysize as u64;

    // Compute Ltree
    set_ltree_adrs(ltree_addr, idx);
    l_tree(
        hash_func,
        wotsParams,
        &mut pkhash,
        &mut wots_pk,
        &pub_seed,
        ltree_addr,
    );

    // Compute root
    validate_authpath(
        hash_func,
        &mut root,
        &pkhash,
        idx as u64,
        sig_msg,
        n,
        h.into(),
        &pub_seed,
        node_addr,
    );

    sig_msg = sig_msg.get(h as usize * n as usize..sig_msg.len()).unwrap();
    sig_msg_len -= h as u64 * n as u64;

    for i in 0..n as usize {
        if root[i] != pk[i] {
            for i in 0..sig_msg_len as usize {
                msg[i] = 0;
            }
            return -1;
        }
    }

    for i in 0..sig_msg_len as usize {
        msg[i] = sig_msg[i];
    }

    return 0;
}
