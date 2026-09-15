use qrllib::rust_wrapper::xmss_alt::{
    algsxmss::{xmss_gen_keypair, xmss_sign_msg},
    algsxmss_fast::{
        xmss_fast_gen_keypair, xmss_fast_sign_msg, xmss_fast_update, BDSState, TreeHashInst,
    },
    fips202::{shake128, shake256},
    hash::{core_hash, h_msg, hash_f, hash_h},
    hash_functions::HashFunction,
    xmss_common::{xmss_verify_sig, XMSSParams},
};

const N: usize = 32;
const SECRET_KEY_SIZE: usize = 132;
const SEED_SIZE: usize = 48;

#[test]
fn hash_entry_points_reject_malformed_lengths_and_clear_outputs() {
    let mut output = vec![0xa5; N];
    assert_ne!(
        0,
        core_hash(
            &HashFunction::Shake128,
            &mut output,
            2,
            &[0; N],
            N as u32,
            &[0; N - 1],
            N as u32,
            N as u32,
        )
    );
    assert!(output.iter().all(|byte| *byte == 0));

    output.fill(0xa5);
    assert_ne!(
        0,
        h_msg(
            &HashFunction::Shake128,
            &mut output,
            &[],
            u32::MAX as u64 + 1,
            &[0; 3 * N],
            (3 * N) as u32,
            N as u32,
        )
    );
    assert!(output.iter().all(|byte| *byte == 0));

    let mut address = [0_u32; 8];
    output.fill(0xa5);
    assert_ne!(
        0,
        hash_f(
            &HashFunction::Shake128,
            &mut output,
            &[0; N - 1],
            &[0; N],
            &mut address,
            N as u32,
        )
    );
    assert!(output.iter().all(|byte| *byte == 0));

    output.fill(0xa5);
    assert_ne!(
        0,
        hash_h(
            &HashFunction::Shake128,
            &mut output,
            &[0; 2 * N - 1],
            &[0; N],
            &mut address,
            N as u32,
        )
    );
    assert!(output.iter().all(|byte| *byte == 0));
}

#[test]
fn shake_entry_points_reject_malformed_lengths_and_clear_outputs() {
    let mut output = [0xa5; 32];
    shake128(&mut output, 33, &[], 0);
    assert!(output.iter().all(|byte| *byte == 0));

    output.fill(0xa5);
    let output_length = output.len();
    shake256(&mut output, output_length, &[0], 2);
    assert!(output.iter().all(|byte| *byte == 0));
}

fn signature_size(params: &XMSSParams) -> usize {
    4 + N + params.wots_par.keysize as usize + params.h as usize * N
}

fn bds_state(height: u8) -> BDSState {
    let k = 2_usize;
    let treehash = (0..height as usize - k)
        .map(|_| {
            let mut treehash = TreeHashInst::default();
            treehash.node = vec![0; N];
            treehash
        })
        .collect();

    BDSState {
        stack: vec![0; (height as usize + 1) * N],
        stackoffset: 0,
        stacklevels: vec![0; height as usize + 1],
        auth: vec![0; height as usize * N],
        keep: vec![0; (height as usize >> 1) * N],
        treehash,
        retain: vec![0; ((1 << k) - k - 1) * N],
        next_leaf: 0,
    }
}

#[test]
fn xmss_fast_leons() {
    let height = 4;
    let params = XMSSParams::new(N as u32, height as u32, 16, 2).unwrap();
    let mut pk = vec![0; 2 * N];
    let mut sk = vec![0; SECRET_KEY_SIZE];
    let mut seed = vec![0; SEED_SIZE];
    let mut state = bds_state(height);

    assert!(xmss_fast_gen_keypair(
        &HashFunction::Shake128,
        &params,
        &mut pk,
        &mut sk,
        &mut state,
        &mut seed,
    )
    .is_ok());
    xmss_fast_update(&HashFunction::Shake128, &params, &mut sk, &mut state, 10).unwrap();

    let mut message = vec![0; N];
    let mut signature = vec![0; signature_size(&params)];
    assert_eq!(
        0,
        xmss_fast_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut sk,
            &mut state,
            &mut signature,
            &message,
            message.len(),
        )
    );
    assert_eq!(
        0,
        xmss_verify_sig(
            &HashFunction::Shake128,
            &params.wots_par,
            &mut message,
            N,
            &signature,
            &pk,
            height,
        )
    );

    message[0] ^= 1;
    assert_ne!(
        0,
        xmss_verify_sig(
            &HashFunction::Shake128,
            &params.wots_par,
            &mut message,
            N,
            &signature,
            &pk,
            height,
        )
    );
    message[0] ^= 1;

    let mut next_signature = vec![0; signature_size(&params)];
    assert_eq!(
        0,
        xmss_fast_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut sk,
            &mut state,
            &mut next_signature,
            &message,
            message.len(),
        )
    );
    assert_eq!(&next_signature[..4], &[0, 0, 0, 11]);
    assert_eq!(
        0,
        xmss_verify_sig(
            &HashFunction::Shake128,
            &params.wots_par,
            &mut message,
            N,
            &next_signature,
            &pk,
            height,
        )
    );

    let mut corrupted_wots = next_signature.clone();
    corrupted_wots[4 + N] ^= 1;
    assert_ne!(
        0,
        xmss_verify_sig(
            &HashFunction::Shake128,
            &params.wots_par,
            &mut message,
            N,
            &corrupted_wots,
            &pk,
            height,
        )
    );

    let mut corrupted_auth_path = next_signature;
    let auth_path_offset = 4 + N + params.wots_par.keysize as usize;
    corrupted_auth_path[auth_path_offset] ^= 1;
    assert_ne!(
        0,
        xmss_verify_sig(
            &HashFunction::Shake128,
            &params.wots_par,
            &mut message,
            N,
            &corrupted_auth_path,
            &pk,
            height,
        )
    );
}

#[test]
fn rejects_unsupported_xmss_parameters() {
    for height in [0, 2, 3, 31, 32, u32::MAX] {
        assert!(XMSSParams::new(N as u32, height, 16, 2).is_err());
    }
    for wots in [0, 3, 8, 32, u32::MAX] {
        assert!(XMSSParams::new(N as u32, 4, wots, 2).is_err());
    }
    for wots in [2, 4, 16, 256] {
        assert!(XMSSParams::new(N as u32, 4, wots, 2).is_ok());
    }
    assert!(XMSSParams::new(31, 4, 16, 2).is_err());
    assert!(XMSSParams::new(N as u32, 4, 16, 1).is_err());
}

#[test]
fn raw_entry_points_reject_malformed_buffers_without_panicking() {
    let height = 4;
    let params = XMSSParams::new(N as u32, height as u32, 16, 2).unwrap();
    let expected_signature_size = signature_size(&params);
    let mut pk = vec![0; 2 * N];
    let mut sk = vec![0; SECRET_KEY_SIZE];
    let mut seed = vec![0; SEED_SIZE];
    let mut state = bds_state(height);

    let mut malformed_pk = vec![0xa5; 2 * N - 1];
    let mut rejected_sk = vec![0xa5; SECRET_KEY_SIZE];
    assert!(xmss_fast_gen_keypair(
        &HashFunction::Shake128,
        &params,
        &mut malformed_pk,
        &mut rejected_sk,
        &mut state,
        &mut seed,
    )
    .is_err());
    assert!(malformed_pk.iter().all(|byte| *byte == 0));
    assert!(rejected_sk.iter().all(|byte| *byte == 0));

    let mut basic_pk = vec![0xa5; 2 * N];
    let mut basic_sk = vec![0xa5; SECRET_KEY_SIZE];
    assert_ne!(
        0,
        xmss_gen_keypair(
            &HashFunction::Shake128,
            &params,
            &mut basic_pk,
            &mut basic_sk[..SECRET_KEY_SIZE - 1],
            &mut seed,
        )
    );
    assert!(basic_pk.iter().all(|byte| *byte == 0));
    assert!(basic_sk[..SECRET_KEY_SIZE - 1]
        .iter()
        .all(|byte| *byte == 0));
    basic_sk[SECRET_KEY_SIZE - 1] = 0;

    let message = vec![0; N];
    let mut short_signature = vec![0xa5; expected_signature_size - 1];
    assert_ne!(
        0,
        xmss_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut basic_sk,
            &mut short_signature,
            &message,
            message.len(),
        )
    );
    assert!(short_signature.iter().all(|byte| *byte == 0));
    short_signature.fill(0xa5);
    assert_ne!(
        0,
        xmss_fast_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut sk,
            &mut state,
            &mut short_signature,
            &message,
            message.len(),
        )
    );
    assert!(short_signature.iter().all(|byte| *byte == 0));

    let mut oversized_signature = vec![0xa5; expected_signature_size + 1];
    assert_ne!(
        0,
        xmss_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut basic_sk,
            &mut oversized_signature,
            &message,
            message.len(),
        )
    );
    assert!(oversized_signature.iter().all(|byte| *byte == 0));
    oversized_signature.fill(0xa5);
    assert_ne!(
        0,
        xmss_fast_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut sk,
            &mut state,
            &mut oversized_signature,
            &message,
            message.len(),
        )
    );
    assert!(oversized_signature.iter().all(|byte| *byte == 0));

    state.stackoffset = height as u32 + 1;
    let mut exact_signature = vec![0xa5; expected_signature_size];
    assert_ne!(
        0,
        xmss_fast_sign_msg(
            &HashFunction::Shake128,
            &params,
            &mut sk,
            &mut state,
            &mut exact_signature,
            &message,
            message.len(),
        )
    );
    assert!(exact_signature.iter().all(|byte| *byte == 0));

    let mut verify_message = message.clone();
    for length in [0, expected_signature_size - 1, expected_signature_size + 1] {
        let malformed_signature = vec![0; length];
        assert_ne!(
            0,
            xmss_verify_sig(
                &HashFunction::Shake128,
                &params.wots_par,
                &mut verify_message,
                N,
                &malformed_signature,
                &pk,
                height,
            )
        );
    }
}
