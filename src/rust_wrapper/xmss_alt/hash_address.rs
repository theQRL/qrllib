pub fn set_layer_adrs(adrs: &mut [u32], layer: u32) {
    adrs[0] = layer;
}

pub fn set_tree_adrs(adrs: &mut [u32], tree: u64) {
    adrs[1] = (tree >> 32) as u32;
    adrs[2] = tree as u32;
}

pub fn set_type(adrs: &mut [u32], type_t: u32) {
    adrs[3] = type_t;
    for i in 4..8 {
        adrs[i] = 0;
    }
}

pub fn set_key_and_mask(adrs: &mut [u32], key_and_mask: u32) {
    adrs[7] = key_and_mask;
}

// OTS

pub fn set_ots_adrs(adrs: &mut [u32], ots: u32) {
    adrs[4] = ots;
}

pub fn set_chain_adrs(adrs: &mut [u32], chain: u32) {
    adrs[5] = chain;
}

pub fn set_hash_adrs(adrs: &mut [u32], hash: u32) {
    adrs[6] = hash;
}

// L-tree

pub fn set_ltree_adrs(adrs: &mut [u32], ltree: u32) {
    adrs[4] = ltree;
}

// Hash Tree & L-tree

pub fn set_tree_height(adrs: &mut [u32], tree_height: u32) {
    adrs[5] = tree_height;
}

pub fn set_tree_index(adrs: &mut [u32], tree_index: u32) {
    adrs[6] = tree_index;
}
