use super::fips202::shake256;
use super::hash::{addr_to_byte, h_msg, hash_h, prf};
use super::hash_address::{
    set_chain_adrs, set_hash_adrs, set_key_and_mask, set_ltree_adrs, set_ots_adrs, set_tree_height,
    set_tree_index, set_type,
};
use super::hash_functions::HashFunction;
use super::wots::{wots_pkgen, wots_sign};
use super::xmss_common::{l_tree, to_byte, XMSSParams};

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

pub fn gen_leaf_wots(
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

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */

fn treehash(
    hash_func: &HashFunction,
    node: &mut [u8],
    height: u16,
    index: u32,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &[u8],
    addr: &[u32; 8],
) {
    let n = params.n;
    // use three different addresses because at this point we use all three formats in parallel
    let mut ots_addr: [u32; 8] = [0; 8];
    let mut ltree_addr: [u32; 8] = [0; 8];
    let mut node_addr: [u32; 8] = [0; 8];
    // only copy layer and tree address parts
    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    // type = ots

    set_type(&mut ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(&mut ltree_addr, 1);
    node_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(&mut node_addr, 2);

    let mut stack: Vec<u8> = vec![0; ((height + 1) as u32 * n) as usize];
    let mut stacklevels: Vec<u16> = vec![0; height as usize + 1];
    let mut stackoffset = 0;

    let lastnode: u32 = index + (1 << height);

    for idx in index..lastnode {
        set_ltree_adrs(&mut ltree_addr, idx);
        set_ots_adrs(&mut ots_addr, idx);
        let stack_length = stack.len();
        let leaf = stack
            .get_mut((stackoffset * n) as usize..stack_length)
            .unwrap();
        gen_leaf_wots(
            hash_func,
            leaf,
            sk_seed,
            params,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
        );
        stacklevels[stackoffset as usize] = 0;
        stackoffset += 1;
        while stackoffset > 1
            && stacklevels[stackoffset as usize - 1] == stacklevels[stackoffset as usize - 2]
        {
            set_tree_height(&mut node_addr, stacklevels[stackoffset as usize - 1].into());
            set_tree_index(
                &mut node_addr,
                idx >> (stacklevels[stackoffset as usize - 1] + 1),
            );
            let mut input = vec![0 as u8; stack_length - ((stackoffset - 2) * n) as usize];
            input.copy_from_slice(
                stack
                    .get(((stackoffset - 2) * n) as usize..stack_length)
                    .unwrap(),
            );
            let out = stack
                .get_mut(((stackoffset - 2) * n) as usize..stack_length)
                .unwrap();
            hash_h(hash_func, out, &input, pub_seed, &mut node_addr, n);
            stacklevels[stackoffset as usize - 2] += 1;
            stackoffset -= 1;
        }
    }
    for i in 0..n as usize {
        node[i] = stack[i];
    }
}

/**
 * Computes the authpath and the root. This method is using a lot of space as we build the whole tree and then select the authpath nodes.
 * For more efficient algorithms see e.g. the chapter on hash-based signatures in Bernstein, Buchmann, Dahmen. "Post-quantum Cryptography", Springer 2009.
 * It returns the authpath in "authpath" with the node on level 0 at index 0.
 */
fn compute_authpath_wots(
    hash_func: &HashFunction,
    root: &mut [u8],
    authpath: &mut [u8],
    leaf_idx: u64,
    sk_seed: &[u8],
    params: &XMSSParams,
    pub_seed: &mut [u8],
    addr: &[u32; 8],
) {
    let n = params.n;
    let h = params.h;

    let tree_length = (2 * (1 << h) * n) as usize;
    let mut tree: Vec<u8> = vec![0; tree_length];

    let ots_addr: &mut [u32; 8] = &mut [0; 8];
    let ltree_addr: &mut [u32; 8] = &mut [0; 8];
    let node_addr: &mut [u32; 8] = &mut [0; 8];

    ots_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ots_addr, 0);
    ltree_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(ltree_addr, 1);
    node_addr[0..3].copy_from_slice(&addr[0..3]);
    set_type(node_addr, 2);

    // Compute all leaves
    for i in 0..(1 << h) {
        set_ltree_adrs(ltree_addr, i);
        set_ots_adrs(ots_addr, i);
        let tree_length = tree.len();
        let leaf_start = ((1 << h) * n + i * n) as usize;
        let leaf = tree.get_mut(leaf_start..tree_length).unwrap();
        gen_leaf_wots(
            hash_func, leaf, sk_seed, params, pub_seed, ltree_addr, ots_addr,
        );
    }

    let mut level = 0;
    // Compute tree:
    // Outer loop: For each inner layer
    let mut i = 1 << h;
    while i > 1 {
        set_tree_height(node_addr, level);
        // Inner loop: for each pair of sibling nodes
        for j in (0..i).step_by(2) {
            set_tree_index(node_addr, j >> 1);
            let tree_length = tree.len();
            let mut input = vec![0; tree_length - (i * n + j * n) as usize];
            input.copy_from_slice(tree.get((i * n + j * n) as usize..tree_length).unwrap());
            let out_start = ((i >> 1) * n + (j >> 1) * n) as usize;
            let out = tree.get_mut(out_start..tree_length).unwrap();
            hash_h(hash_func, out, &input, pub_seed, node_addr, n);
        }
        level += 1;
        i >>= 1;
    }

    // copy authpath
    for i in 0..h {
        let dest = authpath
            .get_mut((i * n) as usize..((i * n) + n) as usize)
            .unwrap();
        let src_start = (((1 << h) >> i) * n + (((leaf_idx >> i) ^ 1) as u32) * n) as usize;
        let src_end = src_start + n as usize;
        let src = tree.get(src_start..src_end).unwrap();
        dest.copy_from_slice(src);
    }

    // copy root
    root.copy_from_slice(tree.get(n as usize..(n + n) as usize).unwrap());
}

pub fn xmss_gen_keypair(
    hash_func: &HashFunction,
    params: &XMSSParams,
    pk: &mut [u8],
    sk: &mut [u8],
    seed: &mut [u8],
) -> u32 {
    let n = params.n;
    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;

    //Construct SK_SEED (n byte), SK_PRF (n byte), and PUB_SEED (n byte) from n-byte seed
    let mut randombits: Vec<u8> = vec![0; 3 * n as usize];
    shake256(&mut randombits, 3 * n as usize, seed, 48);

    // Copy PUB_SEED to public key
    let dest = sk.get_mut(4..4 + (3 * n) as usize).unwrap();
    let src = randombits.get(0..(3 * n) as usize).unwrap();
    dest.copy_from_slice(src);

    let dest = pk.get_mut(n as usize..(2 * n) as usize).unwrap();
    let src = sk
        .get((4 + (2 * n)) as usize..((4 + (2 * n)) + n) as usize)
        .unwrap();
    dest.copy_from_slice(src);

    let addr: &mut [u32; 8] = &mut [0; 8];
    let sk_len = sk.len();
    let sk_seed = sk.get(4..sk_len).unwrap();
    let pub_seed = sk.get(4 + (2 * n) as usize..sk_len).unwrap();
    // Compute root
    treehash(
        hash_func,
        pk,
        params.h.try_into().unwrap(),
        0,
        sk_seed,
        params,
        pub_seed,
        addr,
    );
    // copy root to sk
    let dest = sk
        .get_mut(4 + (3 * n) as usize..(4 + (4 * n)) as usize)
        .unwrap();
    let src = pk.get(0..n as usize).unwrap();
    dest.copy_from_slice(src);
    0
}

pub fn xmss_update_sk(sk: &mut [u8], k: u64) -> i32 {
    //unsigned long idxkey=0;
    //idxkey = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
    let idxkey: u32 =
        ((sk[0] as u32) << 24) | ((sk[1] as u32) << 16) | ((sk[2] as u32) << 8) | sk[3] as u32;
    if idxkey as u64 >= k {
        return -1;
        //the secret key is updated more than the blockchain, so all fine
    } else {
        let idx = k;
        //update secret key index
        sk[0] = ((idx) >> 24) as u8 & 255;
        sk[1] = ((idx) >> 16) as u8 & 255;
        sk[2] = ((idx) >> 8) as u8 & 255;
        sk[3] = (idx) as u8 & 255;
        return 0;
    }
}

pub fn xmss_sign_msg(
    hash_func: &HashFunction,
    params: &XMSSParams,
    sk: &mut [u8],
    mut sig_msg: &mut [u8],
    msg: &mut [u8],
    msglen: usize,
) -> u32 {
    let n: u16 = params.n as u16;

    // Extract SK
    let idx =
        ((sk[0] as u32) << 24) | ((sk[1] as u32) << 16) | ((sk[2] as u32) << 8) | sk[3] as u32;

    let mut sk_seed: Vec<u8> = vec![0; n as usize];
    let dest = sk_seed.get_mut(0..n as usize).unwrap();
    let src = sk.get(4..4 + n as usize).unwrap();
    dest.copy_from_slice(src);

    let mut sk_prf: Vec<u8> = vec![0; n as usize];
    let dest = sk_prf.get_mut(0..n as usize).unwrap();
    let src = sk.get(4 + n as usize..4 + (2 * n) as usize).unwrap();
    dest.copy_from_slice(src);

    let mut pub_seed: Vec<u8> = vec![0; n as usize];
    let dest = pub_seed.get_mut(0..n as usize).unwrap();
    let src = sk.get(4 + (2 * n) as usize..4 + (3 * n) as usize).unwrap();
    dest.copy_from_slice(src);

    // index as 32 bytes string
    let mut idx_bytes_32: Vec<u8> = vec![0; 32];
    to_byte(&mut idx_bytes_32, idx.into(), 32);

    let mut hash_key: Vec<u8> = vec![0; 3 * n as usize];

    // Update SK
    sk[0] = ((idx + 1) >> 24) as u8 & 255;
    sk[1] = ((idx + 1) >> 16) as u8 & 255;
    sk[2] = ((idx + 1) >> 8) as u8 & 255;
    sk[3] = (idx + 1) as u8 & 255;
    // -- Secret key for this non-forward-secure version is now updated.
    // -- A productive implementation should use a file handle instead and write the updated secret key at this point!

    // Init working params
    let mut R: Vec<u8> = vec![0; n as usize];
    let mut msg_h: Vec<u8> = vec![0; n as usize];
    let mut root: Vec<u8> = vec![0; n as usize];
    let mut ots_seed: Vec<u8> = vec![0; n as usize];
    let ots_addr: &mut [u32; 8] = &mut [0; 8];

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(hash_func, &mut R, &idx_bytes_32, &sk_prf, n.into());
    // Generate hash key (R || root || idx)
    let dest = hash_key.get_mut(0..n as usize).unwrap();
    let src = R.get(0..n as usize).unwrap();
    dest.copy_from_slice(src);

    let dest = hash_key.get_mut(n as usize..2 * n as usize).unwrap();
    let src = sk.get(4 + (3 * n) as usize..4 + (4 * n) as usize).unwrap();
    dest.copy_from_slice(src);

    let hash_key_len = hash_key.len();
    let out = hash_key.get_mut(2 * n as usize..hash_key_len).unwrap();
    to_byte(out, idx.into(), n.into());
    // Then use it for message digest
    h_msg(
        hash_func,
        &mut msg_h,
        msg,
        msglen.try_into().unwrap(),
        &hash_key,
        3 * n as u32,
        n.into(),
    );

    // Start collecting signature
    let mut _sig_msg_len: u64 = 0;

    // Copy index to signature
    sig_msg[0] = (idx >> 24) as u8 & 255;
    sig_msg[1] = (idx >> 16) as u8 & 255;
    sig_msg[2] = (idx >> 8) as u8 & 255;
    sig_msg[3] = idx as u8 & 255;

    let sig_msg_length = sig_msg.len();
    sig_msg = sig_msg.get_mut(4..sig_msg_length).unwrap();
    _sig_msg_len += 4;

    // Copy R to signature
    for i in 0..n {
        sig_msg[i as usize] = R[i as usize];
    }
    let sig_msg_length = sig_msg.len();
    sig_msg = sig_msg.get_mut(n as usize..sig_msg_length).unwrap();
    _sig_msg_len += n as u64;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    set_type(ots_addr, 0);
    set_ots_adrs(ots_addr, idx);

    // Compute seed for OTS key pair
    get_seed(hash_func, &mut ots_seed, &sk_seed, n.into(), ots_addr);

    // Compute WOTS signature
    wots_sign(
        hash_func,
        sig_msg,
        &msg_h,
        &ots_seed,
        &(params.wots_par),
        &pub_seed,
        ots_addr,
    );

    let sig_msg_length = sig_msg.len();
    sig_msg = sig_msg
        .get_mut(params.wots_par.keysize as usize..sig_msg_length)
        .unwrap();
    _sig_msg_len += params.wots_par.keysize as u64;

    compute_authpath_wots(
        hash_func,
        &mut root,
        sig_msg,
        idx as u64,
        &sk_seed,
        params,
        &mut pub_seed,
        ots_addr,
    );
    //let sig_msg_length = sig_msg.len();
    // sig_msg = sig_msg
    //     .get_mut((params.h * n as u32) as usize..sig_msg_length)
    //     .unwrap();
    _sig_msg_len += (params.h * n as u32) as u64;

    //Whipe secret elements?
    //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

    //  memcpy(sig_msg, msg, msglen);
    //sig_msg_len += msglen;
    return 0;
}
