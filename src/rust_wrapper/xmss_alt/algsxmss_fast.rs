use super::fips202::shake256;
use super::hash::{addr_to_byte, h_msg, hash_h, prf};
use super::hash_address::{
    set_chain_adrs, set_hash_adrs, set_key_and_mask, set_ltree_adrs, set_ots_adrs, set_tree_height,
    set_tree_index, set_type,
};
use super::hash_functions::HashFunction;
use super::wots::{wots_pkgen, wots_sign};
use super::xmss_common::{l_tree, to_byte, XMSSParams};
use crate::rust_wrapper::errors::QRLError;

#[derive(Clone, Default)]
pub struct TreeHashInst {
    h: u32,
    next_idx: u32,
    stackusage: u32,
    completed: u8,
    pub node: Vec<u8>,
}

#[derive(Default)]
pub struct BDSState {
    pub stack: Vec<u8>,
    pub stackoffset: u32,
    pub stacklevels: Vec<u8>,
    pub auth: Vec<u8>,
    pub keep: Vec<u8>,
    pub treehash: Vec<TreeHashInst>,
    pub retain: Vec<u8>,
    pub next_leaf: u32,
}

/**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 *
 * takes n byte sk_seed and returns n byte seed using 32 byte address addr.
 */
fn get_seed(
    hash_func: &HashFunction,
    seed: &mut [u8],
    sk_seed: &[u8],
    n: u32,
    addr: &mut [u32; 8],
) {
    let mut bytes: Vec<u8> = vec![0; 32];

    // Make sure that chain addr, hash addr, and key bit are 0!
    set_chain_adrs(addr, 0);
    set_hash_adrs(addr, 0);
    set_key_and_mask(addr, 0);

    // Generate pseudorandom value
    addr_to_byte(&mut bytes, addr);
    prf(hash_func, seed, &bytes, sk_seed, n);
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
fn gen_leaf_wots(
    hash_func: &HashFunction,
    leaf: &mut [u8],
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    ltree_addr: &mut [u32; 8],
    ots_addr: &mut [u32; 8],
) {
    let mut seed: Vec<u8> = vec![0; params.n as usize];
    let mut pk: Vec<u8> = vec![0; params.wots_par.keysize as usize];

    get_seed(hash_func, &mut seed, sk_seed, params.n, ots_addr);
    wots_pkgen(
        hash_func,
        &mut pk,
        &seed,
        &(params.wots_par),
        pub_seed,
        ots_addr,
    );

    l_tree(
        hash_func,
        &params.wots_par,
        leaf,
        &mut pk,
        pub_seed,
        ltree_addr,
    );
}

fn treehash_minheight_on_stack(
    state: &BDSState,
    params: &XMSSParams,
    treehash: &TreeHashInst,
) -> u32 {
    let mut r = params.h;
    for i in 0..treehash.stackusage {
        if (state.stacklevels[(state.stackoffset - i - 1) as usize] as u32) < r {
            r = state.stacklevels[(state.stackoffset - i - 1) as usize] as u32;
        }
    }
    return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
fn treehash_setup(
    hash_func: &HashFunction,
    node: &mut [u8],
    height: u32,
    index: u32,
    state: &mut BDSState,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let n = params.n;
    let h = params.h;
    let k = params.k;
    // use three different addresses because at this point we use all three formats in parallel
    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];
    // only copy layer and tree address parts
    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    // type = ots
    set_type(ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ltree_addr, 1);
    node_addr.copy_from_slice(addr);
    set_type(node_addr, 2);

    let mut stack: Vec<u8> = vec![0; ((height + 1) as u32 * n) as usize];
    let mut stacklevels: Vec<u16> = vec![0; height as usize + 1];
    let mut stackoffset = 0;

    let lastnode = index + (1 << height);

    let bound = h - k;
    for i in 0..bound as usize {
        state.treehash[i].h = i as u32;
        state.treehash[i].completed = 1;
        state.treehash[i].stackusage = 0;
    }

    let mut i = 0;
    for idx in index..lastnode {
        set_ltree_adrs(ltree_addr, idx);
        set_ots_adrs(ots_addr, idx);
        let stack_len = stack.len();
        let leaf = stack
            .get_mut((stackoffset * n) as usize..stack_len)
            .unwrap();
        gen_leaf_wots(
            hash_func, leaf, sk_seed, params, pub_seed, ltree_addr, ots_addr,
        );
        stacklevels[stackoffset as usize] = 0;
        stackoffset += 1;
        if h - k > 0 && i == 3 {
            let dest_option = state.treehash[0].node.get_mut(0..n as usize);
            let src = stack
                .get((stackoffset * n) as usize..((stackoffset * n) + n) as usize)
                .unwrap();
            if let Some(dest) = dest_option {
                dest.copy_from_slice(src);
            } else {
                state.treehash[0].node = src.to_vec();
            }
        }
        while stackoffset > 1
            && stacklevels[stackoffset as usize - 1] == stacklevels[stackoffset as usize - 2]
        {
            let nodeh: u32 = stacklevels[stackoffset as usize - 1].into();
            if i >> nodeh == 1 {
                let dest_option = state
                    .auth
                    .get_mut((nodeh * n) as usize..((nodeh * n) + n) as usize);
                let src = stack
                    .get(((stackoffset - 1) * n) as usize..(((stackoffset - 1) * n) + n) as usize)
                    .unwrap();
                if let Some(dest) = dest_option {
                    dest.copy_from_slice(src);
                } else {
                    state.auth = src.to_vec();
                }
            } else {
                if nodeh < h - k && i >> nodeh == 3 {
                    let dest_option = state.treehash[nodeh as usize].node.get_mut(0..n as usize);
                    let src = stack
                        .get(
                            ((stackoffset - 1) * n) as usize
                                ..(((stackoffset - 1) * n) + n) as usize,
                        )
                        .unwrap();
                    if let Some(dest) = dest_option {
                        dest.copy_from_slice(src);
                    } else {
                        state.treehash[nodeh as usize].node = src.to_vec();
                    }
                } else if nodeh >= h - k {
                    let dest_start = (((1 << (h - 1 - nodeh)) + nodeh - h
                        + (((i >> nodeh) - 3) >> 1))
                        * n) as usize;
                    let dest_option = state.retain.get_mut(dest_start..dest_start + n as usize);
                    let src_start = ((stackoffset - 1) * n) as usize;
                    let src = stack.get(src_start..src_start + n as usize).unwrap();
                    if let Some(dest) = dest_option {
                        dest.copy_from_slice(src);
                    } else {
                        state.retain = src.to_vec();
                    }
                }
            }
            set_tree_height(node_addr, stacklevels[stackoffset as usize - 1].into());
            set_tree_index(
                node_addr,
                idx >> (stacklevels[stackoffset as usize - 1] + 1),
            );
            let mut input: Vec<u8> = Vec::new();
            let start_idx = ((stackoffset - 2) * n) as usize;
            let stack_len = stack.len();
            input.extend_from_slice(stack.get(start_idx..stack_len).unwrap());
            let output = stack.get_mut(start_idx..stack_len).unwrap();
            hash_h(hash_func, output, &input, pub_seed, node_addr, n);
            stacklevels[stackoffset as usize - 2] += 1;
            stackoffset -= 1;
        }
        i += 1;
    }

    for i in 0..n as usize {
        node[i] = stack[i];
    }
}

fn treehash_update(
    hash_func: &HashFunction,
    treehash: &mut TreeHashInst,
    state: &mut BDSState,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &[u32; 8],
) {
    let n = params.n;

    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];
    // only copy layer and tree address parts
    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    // type = ots
    set_type(ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ltree_addr, 1);
    node_addr.copy_from_slice(addr);
    set_type(node_addr, 2);

    set_ltree_adrs(ltree_addr, treehash.next_idx);
    set_ots_adrs(ots_addr, treehash.next_idx);

    let mut nodebuffer: Vec<u8> = vec![0; 2 * n as usize];
    let mut nodeheight: u32 = 0;
    gen_leaf_wots(
        hash_func,
        &mut nodebuffer,
        sk_seed,
        params,
        pub_seed,
        ltree_addr,
        ots_addr,
    );
    while treehash.stackusage > 0
        && state.stacklevels[state.stackoffset as usize - 1] as u32 == nodeheight
    {
        nodebuffer.copy_within(0..n as usize, n as usize);
        let dest = nodebuffer.get_mut(0..n as usize).unwrap();
        let src_start = ((state.stackoffset - 1) * n) as usize;
        let src = state.stack.get(src_start..src_start + n as usize).unwrap();
        dest.copy_from_slice(src);
        set_tree_height(node_addr, nodeheight.into());
        set_tree_index(node_addr, treehash.next_idx >> (nodeheight + 1));
        let mut input: Vec<u8> = vec![];
        input.copy_from_slice(&nodebuffer);
        hash_h(hash_func, &mut nodebuffer, &input, pub_seed, node_addr, n);
        nodeheight += 1;
        treehash.stackusage -= 1;
        state.stackoffset -= 1;
    }
    if nodeheight == treehash.h {
        // this also implies stackusage == 0
        let dest = treehash.node.get_mut(0..n as usize).unwrap();
        let src = nodebuffer.get(0..n as usize).unwrap();
        dest.copy_from_slice(src);
        treehash.completed = 1;
    } else {
        let dest_start = (state.stackoffset * n) as usize;
        let dest = state
            .stack
            .get_mut(dest_start..dest_start + n as usize)
            .unwrap();
        let src = nodebuffer.get(0..n as usize).unwrap();
        dest.copy_from_slice(src);
        treehash.stackusage += 1;
        state.stacklevels[state.stackoffset as usize] = nodeheight as u8;
        state.stackoffset += 1;
        treehash.next_idx += 1;
    }
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
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let n = params.n;

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

    for i in 0..(params.h - 1) {
        set_tree_height(addr, i);
        leafidx >>= 1;
        set_tree_index(addr, leafidx as u32);
        if leafidx & 1 != 0 {
            let mut input: Vec<u8> = vec![];
            input.copy_from_slice(&buffer);
            let buffer_len = buffer.len();
            let output = buffer.get_mut(n as usize..buffer_len).unwrap();
            hash_h(hash_func, output, &input, pub_seed, addr, n);
            for j in 0..n as usize {
                buffer[j] = authpath[j];
            }
        } else {
            let mut input: Vec<u8> = vec![];
            input.copy_from_slice(&buffer);
            hash_h(hash_func, &mut buffer, &input, pub_seed, addr, n);
            for j in 0..n as usize {
                buffer[j + n as usize] = authpath[j];
            }
        }
        authpath = authpath.get(n as usize..authpath.len()).unwrap();
    }
    set_tree_height(addr, params.h - 1);
    leafidx >>= 1;
    set_tree_index(addr, leafidx as u32);
    hash_h(hash_func, root, &buffer, pub_seed, addr, n);
}

/**
 * Performs one treehash update on the instance that needs it the most.
 * Returns 1 if such an instance was not found
 **/
fn bds_treehash_update(
    hash_func: &HashFunction,
    state: &mut BDSState,
    updates: u32,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &[u32; 8],
) -> u8 {
    let h = params.h;
    let k = params.k;
    let mut used = 0;

    for _j in 0..updates {
        let mut l_min = h;
        let mut level = h - k;
        for i in 0..(h - k) as usize {
            let low = if state.treehash[i].completed != 0 {
                h
            } else if state.treehash[i].stackusage == 0 {
                i as u32
            } else {
                treehash_minheight_on_stack(state, params, &(state.treehash[i]))
            };
            if low < l_min {
                level = i as u32;
                l_min = low;
            }
        }
        if level == h - k {
            break;
        }
        let treehash = &mut state.treehash[level as usize].clone();
        treehash_update(hash_func, treehash, state, sk_seed, params, pub_seed, addr);
        state.treehash[level as usize] = treehash.to_owned();
        used += 1;
    }
    return (updates - used) as u8;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns 1 if all leaf nodes have already been processed
 **/
fn bds_state_update(
    hash_func: &HashFunction,
    state: &mut BDSState,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &[u32; 8],
) -> u8 {
    let XMSS_N = params.n;
    let XMSS_TREEHEIGHT = params.h;
    let XMSS_BDS_K = params.k;

    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];

    let idx = state.next_leaf;
    if idx == 1 << XMSS_TREEHEIGHT {
        return 1;
    }

    // only copy layer and tree address parts
    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    // type = ots
    set_type(ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ltree_addr, 1);
    node_addr.copy_from_slice(addr);
    set_type(node_addr, 2);

    set_ltree_adrs(ltree_addr, idx);
    set_ots_adrs(ots_addr, idx);

    let stack_len = state.stack.len();
    let leaf = state
        .stack
        .get_mut((state.stackoffset * XMSS_N) as usize..stack_len)
        .unwrap();
    gen_leaf_wots(
        hash_func, leaf, sk_seed, params, pub_seed, ltree_addr, ots_addr,
    );

    state.stacklevels[state.stackoffset as usize] = 0;
    state.stackoffset += 1;
    if XMSS_TREEHEIGHT - XMSS_BDS_K > 0 && idx == 3 {
        let dest = state.treehash[0].node.get_mut(0..XMSS_N as usize).unwrap();
        let src_start = (state.stackoffset * XMSS_N) as usize;
        let src = state
            .stack
            .get(src_start..src_start + XMSS_N as usize)
            .unwrap();
        dest.copy_from_slice(src);
    }
    while state.stackoffset > 1
        && state.stacklevels[state.stackoffset as usize - 1]
            == state.stacklevels[state.stackoffset as usize - 2]
    {
        let nodeh = state.stacklevels[state.stackoffset as usize - 1] as u32;
        if idx >> nodeh == 1 {
            let dest_start = (nodeh * XMSS_N) as usize;
            let dest = state
                .auth
                .get_mut(dest_start..dest_start + XMSS_N as usize)
                .unwrap();
            let src_start = ((state.stackoffset - 1) * XMSS_N) as usize;
            let src = state
                .stack
                .get(src_start..src_start + XMSS_N as usize)
                .unwrap();
            dest.copy_from_slice(src);
        } else {
            if nodeh < XMSS_TREEHEIGHT - XMSS_BDS_K && idx >> nodeh == 3 {
                let dest = state.treehash[nodeh as usize]
                    .node
                    .get_mut(0..XMSS_N as usize)
                    .unwrap();
                let src_start = ((state.stackoffset - 1) * XMSS_N) as usize;
                let src = state
                    .stack
                    .get(src_start..src_start + XMSS_N as usize)
                    .unwrap();
                dest.copy_from_slice(src);
            } else if nodeh >= XMSS_TREEHEIGHT - XMSS_BDS_K {
                let dest_start = (((1 << (XMSS_TREEHEIGHT - 1 - nodeh)) + nodeh - XMSS_TREEHEIGHT
                    + (((idx >> nodeh) - 3) >> 1))
                    * XMSS_N) as usize;
                let dest = state
                    .retain
                    .get_mut(dest_start..dest_start + XMSS_N as usize)
                    .unwrap();
                let src_start = ((state.stackoffset - 1) * XMSS_N) as usize;
                let src = state
                    .stack
                    .get(src_start..src_start + XMSS_N as usize)
                    .unwrap();
                dest.copy_from_slice(src);
            }
        }

        set_tree_height(
            node_addr,
            state.stacklevels[state.stackoffset as usize - 1] as u32,
        );
        set_tree_index(
            node_addr,
            idx >> (state.stacklevels[state.stackoffset as usize - 1] + 1),
        );

        let output_start = ((state.stackoffset - 2) * XMSS_N) as usize;
        let stack_len = state.stack.len();
        let output = state.stack.get_mut(output_start..stack_len).unwrap();
        let mut input = vec![];
        input.copy_from_slice(output);
        hash_h(hash_func, output, &input, pub_seed, node_addr, XMSS_N);

        state.stacklevels[state.stackoffset as usize - 2] += 1;
        state.stackoffset -= 1;
    }
    state.next_leaf += 1;
    return 0;
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
fn bds_round(
    hash_func: &HashFunction,
    state: &mut BDSState,
    leaf_idx: u64,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &mut [u32; 8],
) {
    let n = params.n;
    let h = params.h;
    let k = params.k;

    let mut tau = h;
    let mut buf: Vec<u8> = vec![0; 2 * n as usize];

    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];

    // only copy layer and tree address parts
    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    // type = ots
    set_type(ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ltree_addr, 1);
    node_addr.copy_from_slice(addr);
    set_type(node_addr, 2);

    for i in 0..h {
        if !((leaf_idx >> i) & 1) != 0 {
            tau = i;
            break;
        }
    }

    if tau > 0 {
        let dest = buf.get_mut(0..n as usize).unwrap();
        let src_start = ((tau - 1) * n) as usize;
        let src = state.auth.get(src_start..src_start + n as usize).unwrap();
        dest.copy_from_slice(src);

        // we need to do this before refreshing state.keep to prevent overwriting
        let dest = buf.get_mut(n as usize..(n + n) as usize).unwrap();
        let src_start = (((tau - 1) >> 1) * n) as usize;
        let src = state.keep.get(src_start..src_start + n as usize).unwrap();
        dest.copy_from_slice(src);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) != 0) && (tau < h - 1) {
        let dest_start = ((tau >> 1) * n) as usize;
        let dest = state
            .keep
            .get_mut(dest_start..dest_start + n as usize)
            .unwrap();
        let src_start = (tau * n) as usize;
        let src = state.auth.get(src_start..src_start + n as usize).unwrap();
        dest.copy_from_slice(src);
    }
    if tau == 0 {
        set_ltree_adrs(ltree_addr, leaf_idx as u32);
        set_ots_adrs(ots_addr, leaf_idx as u32);
        gen_leaf_wots(
            hash_func,
            &mut state.auth,
            sk_seed,
            params,
            pub_seed,
            ltree_addr,
            ots_addr,
        );
    } else {
        set_tree_height(node_addr, tau - 1);
        set_tree_index(node_addr, (leaf_idx >> tau) as u32);
        let state_auth_len = state.auth.len();
        let out = state
            .auth
            .get_mut((tau * n) as usize..state_auth_len)
            .unwrap();
        hash_h(hash_func, out, &buf, pub_seed, node_addr, n);
        for i in 0..tau {
            if i < h - k {
                let dest = state
                    .auth
                    .get_mut((i * n) as usize..((i * n) + n) as usize)
                    .unwrap();
                let src = state.treehash[i as usize].node.get(0..n as usize).unwrap();
                dest.copy_from_slice(src);
            } else {
                let offset = (1 << (h - 1 - i)) + i - h;
                let rowidx = ((leaf_idx >> i) - 1) >> 1;
                let dest = state
                    .auth
                    .get_mut((i * n) as usize..((i * n) + n) as usize)
                    .unwrap();
                let src_start = ((offset + rowidx as u32) * n) as usize;
                let src = state.retain.get(src_start..src_start + n as usize).unwrap();
                dest.copy_from_slice(src);
            }
        }

        for i in 0..(if tau < h - k { tau } else { h - k }) as usize {
            let startidx = leaf_idx + 1 + 3 * (1 << i);
            if startidx < 1 << h {
                state.treehash[i].h = i as u32;
                state.treehash[i].next_idx = startidx as u32;
                state.treehash[i].completed = 0;
                state.treehash[i].stackusage = 0;
            }
        }
    }
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
pub fn xmss_fast_gen_keypair(
    hash_func: &HashFunction,
    params: &XMSSParams, // TODO: Refactor this. Remove params, etc.
    pk: &mut [u8],
    sk: &mut [u8],
    state: &mut BDSState,
    seed: &mut [u8],
) -> Result<(), QRLError> {
    if (params.h & 1) != 0 {
        return Err(QRLError::InvalidArgument(
            "Not a valid h, only even numbers supported! Try again with an even number".to_owned(),
        ));
    }
    let n = params.n;

    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    // Copy PUB_SEED to public key
    let mut randombits: Vec<u8> = vec![0; 3 * n as usize];
    shake256(&mut randombits, 3 * n as usize, seed, 48); // FIXME: seed size has been hardcoded to 48
    let rnd: usize = 96;
    let pks: usize = 32;

    let dest = sk.get_mut(4..4 + rnd as usize).unwrap();
    dest.copy_from_slice(randombits.get(0..rnd).unwrap());

    let dest = pk.get_mut(n as usize..pks + n as usize).unwrap();
    let src_start = (4 + (2 * n)) as usize;
    let src = sk.get(src_start..src_start + pks).unwrap();
    dest.copy_from_slice(src);

    let addr: &mut [u32; 8] = &mut [0; 8];

    // Compute root
    treehash_setup(
        hash_func,
        pk,
        params.h,
        0,
        state,
        sk.get(4..sk.len()).unwrap(),
        params,
        sk.get(4 + (2 * n) as usize..sk.len()).unwrap(),
        addr,
    );

    // copy root to sk
    let dest_start = (4 + 3 * n) as usize;
    let dest = sk.get_mut(dest_start..dest_start + pks).unwrap();
    let src = pk.get(0..pks).unwrap();
    dest.copy_from_slice(src);

    return Ok(());
}

pub fn xmss_fast_update(
    hash_func: &HashFunction,
    params: &XMSSParams,
    sk: &mut [u8],
    state: &mut BDSState,
    new_idx: u32,
) -> Result<i32, QRLError> {
    let num_elems = 1 << params.h;

    let current_idx =
        ((sk[0] as u32) << 24) | ((sk[1] as u32) << 16) | ((sk[2] as u32) << 8) | sk[3] as u32;

    // Verify ranges
    if new_idx >= num_elems {
        return Err(QRLError::InvalidArgument("index too high".to_string()));
    }

    if new_idx < current_idx {
        return Err(QRLError::InvalidArgument("cannot rewind".to_string()));
    }

    // Change index
    let sk_seed: &mut [u8; 32] = &mut [0; 32];
    let src = sk.get(4..32 + 4).unwrap();
    sk_seed.get_mut(0..32).unwrap().copy_from_slice(src);

    let pub_seed: &mut [u8; 32] = &mut [0; 32];
    let src = sk.get(4 + 2 * 32..4 + 2 * 32 + 32).unwrap();
    pub_seed.get_mut(0..32).unwrap().copy_from_slice(src);

    let ots_addr: &mut [u32; 8] = &mut [0; 8];

    for j in current_idx..new_idx {
        if j >= num_elems {
            return Ok(-1);
        }

        bds_round(
            hash_func, state, j as u64, sk_seed, params, pub_seed, ots_addr,
        );
        bds_treehash_update(
            hash_func,
            state,
            (params.h - params.k) >> 1,
            sk_seed,
            params,
            pub_seed,
            ots_addr,
        );
    }

    //update secret key index
    sk[0] = ((new_idx) >> 24) as u8 & 255;
    sk[1] = ((new_idx) >> 16) as u8 & 255;
    sk[2] = ((new_idx) >> 8) as u8 & 255;
    sk[3] = (new_idx) as u8 & 255;

    return Ok(0);
}

pub fn xmss_fast_sign_msg(
    hash_func: &HashFunction,
    params: &XMSSParams,
    sk: &mut [u8],
    state: &mut BDSState,
    mut sig_msg: &mut [u8],
    msg: &[u8],
    msglen: u64,
) -> u32 {
    let n = params.n;

    // Extract SK
    let idx =
        ((sk[0] as u32) << 24) | ((sk[1] as u32) << 16) | ((sk[2] as u32) << 8) | sk[3] as u32;
    let mut sk_seed: Vec<u8> = vec![0; n as usize];
    sk_seed.copy_from_slice(sk.get(4..4 + n as usize).unwrap());
    let mut sk_prf: Vec<u8> = vec![0; n as usize];
    sk_prf.copy_from_slice(sk.get(4 + n as usize..4 + (n + n) as usize).unwrap());
    let mut pub_seed: Vec<u8> = vec![0; n as usize];
    pub_seed.copy_from_slice(sk.get(4 + 2 * n as usize..4 + 3 * n as usize).unwrap());

    // index as 32 bytes string
    let idx_bytes_32: &mut [u8; 32] = &mut [0; 32];
    to_byte(idx_bytes_32.as_mut_slice(), idx as u64, 32);

    let mut hash_key: Vec<u8> = vec![0; 3 * n as usize];

    // Update SK
    sk[0] = ((idx + 1) >> 24) as u8 & 255;
    sk[1] = ((idx + 1) >> 16) as u8 & 255;
    sk[2] = ((idx + 1) >> 8) as u8 & 255;
    sk[3] = (idx + 1) as u8 & 255;
    // -- Secret key for this non-forward-secure version is now updated.
    // -- A productive implementation should use a file handle instead and write the updated secret key at this point!
    let mut _sig_msg_len: u64;
    // Init working params
    let mut R: Vec<u8> = vec![0; n as usize];
    let mut msg_h: Vec<u8> = vec![0; n as usize];
    let mut ots_seed: Vec<u8> = vec![0; n as usize];
    let ots_addr: &mut [u32; 8] = &mut [0; 8];

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(hash_func, &mut R, idx_bytes_32, &sk_prf, n);
    // Generate hash key (R || root || idx)
    hash_key
        .get_mut(0..n as usize)
        .unwrap()
        .copy_from_slice(R.get(0..n as usize).unwrap());
    let dest = hash_key.get_mut(n as usize..2 * n as usize).unwrap();
    let src = sk.get(4 + 3 * n as usize..4 + 4 * n as usize).unwrap();
    dest.copy_from_slice(src);
    let out = hash_key.get_mut(2 * n as usize..3 * n as usize).unwrap();
    to_byte(out, idx as u64, n);
    // Then use it for message digest
    h_msg(hash_func, &mut msg_h, msg, msglen, &hash_key, 3 * n, n);

    // Start collecting signature
    _sig_msg_len = 0;

    // Copy index to signature
    sig_msg[0] = (idx >> 24) as u8 & 255;
    sig_msg[1] = (idx >> 16) as u8 & 255;
    sig_msg[2] = (idx >> 8) as u8 & 255;
    sig_msg[3] = idx as u8 & 255;

    let _sig_msg_length = sig_msg.len();
    sig_msg = sig_msg.get_mut(4.._sig_msg_length).unwrap();
    _sig_msg_len += 4;

    // Copy R to signature
    for i in 0..n as usize {
        sig_msg[i] = R[i];
    }

    let _sig_msg_length = sig_msg.len();
    sig_msg = sig_msg.get_mut(n as usize.._sig_msg_length).unwrap();
    _sig_msg_len += n as u64;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    set_type(ots_addr, 0);
    set_ots_adrs(ots_addr, idx);

    // Compute seed for OTS key pair
    get_seed(hash_func, &mut ots_seed, &sk_seed, n, ots_addr);

    // Compute WOTS signature
    wots_sign(
        hash_func,
        &mut sig_msg,
        &msg_h,
        &ots_seed,
        &(params.wots_par),
        &pub_seed,
        ots_addr,
    );
    let _sig_msg_length = sig_msg.len();
    sig_msg = sig_msg
        .get_mut(params.wots_par.keysize as usize.._sig_msg_length)
        .unwrap();
    _sig_msg_len += params.wots_par.keysize as u64;

    // the auth path was already computed during the previous round
    let src = state.auth.get(0..(params.h * n) as usize).unwrap();
    sig_msg
        .get_mut(0..(params.h * n) as usize)
        .unwrap()
        .copy_from_slice(src);

    if idx < (1 << params.h) - 1 {
        bds_round(
            hash_func, state, idx as u64, &sk_seed, params, &pub_seed, ots_addr,
        );
        bds_treehash_update(
            hash_func,
            state,
            (params.h - params.k) >> 1,
            &sk_seed,
            params,
            &pub_seed,
            ots_addr,
        );
    }

    // sig_msg += params.h * params.n;
    // sig_msg_len += params.h * params.n;

    //Whipe secret elements?
    //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

    //  memcpy(sig_msg, msg, msglen);
    //*sig_msg_len += msglen;
    //printf("%d",sig_msg_len);
    return 0;
}
