use qrllib::rust_wrapper::xmss_alt::{
    algsxmss_fast::{
        xmss_fast_gen_keypair, xmss_fast_sign_msg, xmss_fast_update, BDSState, TreeHashInst,
    },
    hash_functions::HashFunction,
    xmss_common::{xmss_verify_sig, XMSSParams},
};

#[test]
fn xmss_fast_leons() {
    let h: u8 = 4;
    let siglen: u64 = (4 + 32 + 67 * 32 + (h as u64) * 32);

    let mut pk: [u8; 64] = [0; 64];
    let mut sk: [u8; 4 + 4 * 32] = [0; 4 + 4 * 32];
    let n: u32 = 48;
    let mut seed: [u8; 48] = [0; 48];

    println!("before keygen");

    let k: u32 = 2;
    let stack = vec![0; (h as usize + 1) * n as usize];
    let stackoffset: u32 = 0;
    let stacklevels: Vec<u8> = vec![0; h as usize + 1];
    let auth: Vec<u8> = vec![0; (h as usize) * n as usize];
    let keep: Vec<u8> = vec![0; (h >> 1) as usize * n as usize];
    let treehash: Vec<TreeHashInst> = vec![TreeHashInst::default(); h as usize - k as usize];
    let th_nodes: Vec<u8> = vec![0; (h as usize - k as usize) * n as usize];
    let retain: Vec<u8> = vec![0; ((1 << k) - k - 1) as usize * n as usize];

    let mut state = BDSState {
        stack,
        stackoffset,
        stacklevels,
        auth,
        keep,
        treehash,
        retain,
        next_leaf: 0,
    };

    let params = XMSSParams::new(32, h.into(), 16, 2).unwrap();
    assert!(xmss_fast_gen_keypair(
        &HashFunction::Shake128,
        &params,
        &mut pk,
        &mut sk,
        &mut state,
        &mut seed,
    )
    .is_ok());

    let mut msg: [u8; 32] = [0; 32];
    let mut sign: [u8; 10000] = [0; 10000];

    println!("Sign / Verify");

    let y = xmss_fast_update(&HashFunction::Shake128, &params, &mut sk, &mut state, 10).unwrap();
    let x = xmss_fast_sign_msg(
        &HashFunction::Shake128,
        &params,
        &mut sk,
        &mut state,
        &mut sign,
        &msg,
        32,
    );
    let x = xmss_verify_sig(
        &HashFunction::Shake128,
        &params.wots_par,
        &mut msg,
        32,
        &sign,
        &pk,
        h,
    );

    println!("\n{}", x);

    let m: u64 = 32;
    let x = xmss_fast_sign_msg(
        &HashFunction::Shake128,
        &params,
        &mut sk,
        &mut state,
        &mut sign,
        &msg,
        32,
    );

    msg[10] ^= 1;
    let x = xmss_verify_sig(
        &HashFunction::Shake128,
        &params.wots_par,
        &mut msg,
        32,
        &sign,
        &pk,
        h,
    );

    println!("\n{}", x);

    msg[0] ^= 1;
    let x = xmss_verify_sig(
        &HashFunction::Shake128,
        &params.wots_par,
        &mut msg,
        32,
        &sign,
        &pk,
        h,
    );
    println!("\n{}", x);
    msg[0] ^= 1;
    sign[5 * 32] ^= 1;
    let x = xmss_verify_sig(
        &HashFunction::Shake128,
        &params.wots_par,
        &mut msg,
        32,
        &sign,
        &pk,
        h,
    );
    println!("\n{}", x);
}
