use super::hash::{h_msg, hash_h};
use super::hash_address::{set_ltree_adrs, set_ots_adrs, set_type};
use super::{
    hash_address::{set_tree_height, set_tree_index},
    hash_functions::HashFunction,
    wots::{wots_pk_from_sig, WOTSParams},
};
use std::fmt;

pub struct InitializationError;

impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "For BDS traversal, H - K must be even, with H > K >= 2!")
    }
}

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
    pub fn new(n: u32, h: u32, w: u32, k: u32) -> Result<Self, InitializationError> {
        if k >= h || k < 2 || (h - k) % 2 != 0 {
            Err(InitializationError)
        } else {
            let wots_par = WOTSParams::new(n, w);
            Ok(XMSSParams { wots_par, n, h, k })
        }
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
            input.copy_from_slice(wots_pk.get((i * 2 * n) as usize..wots_pk_length).unwrap());
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
    mut leafidx: u32,
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
        set_tree_index(addr, leafidx);
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
    set_tree_index(addr, leafidx);
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
    let mut sig_msg_len = (4 + 32 + wotsParams.len * 32 + h as u32 * 32) as u64;

    let n = wotsParams.n;

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

    // printf("verify:: idx = %lu\n", idx);

    // Generate hash key (R || root || idx)
    hash_key.copy_from_slice(sig_msg.get(4..n as usize).unwrap());
    let hash_key_len = hash_key.len();
    let hash_key_segment = hash_key.get_mut(n as usize..hash_key_len).unwrap();
    hash_key_segment.copy_from_slice(pk.get(0..n as usize).unwrap());
    let to_byte_out = hash_key.get_mut(2 * n as usize..hash_key_len).unwrap();
    to_byte(to_byte_out, idx.into(), n);

    sig_msg = sig_msg.get(n as usize + 4..sig_msg.len()).unwrap();
    sig_msg_len -= n as u64 + 4;

    // hash message
    h_msg(
        hash_func,
        &mut msg_h,
        msg,
        msglen.try_into().unwrap(),
        &hash_key,
        3 * n,
        n,
    );
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
        idx,
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
                return -1;
            }
        }
    }

    for i in 0..sig_msg_len as usize {
        msg[i] = sig_msg[i];
    }

    return 0;
}
