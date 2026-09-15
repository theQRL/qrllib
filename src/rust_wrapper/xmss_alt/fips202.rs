/*
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136

void shake128(unsigned char *out,
              unsigned long long outlen,
              const unsigned char *in,
              unsigned long long inlen);

void shake256(unsigned char *out,
              unsigned long long outlen,
              const unsigned char *in,
              unsigned long long inlen);
              */

const NROUNDS: usize = 24;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

use zeroize::Zeroizing;

fn load64(x: &[u8]) -> u64 {
    let mut r: u64 = 0;

    for i in 0..8 {
        r |= (x[i] as u64) << (8 * i);
    }
    r
}

fn store64(x: &mut [u8], mut u: u64) {
    for i in 0..8 {
        x[i] = u as u8;
        u >>= 8;
    }
}

const KECCAK_F_ROUND_CONSTANTS: [u64; NROUNDS] = [
    0x0000000000000001u64,
    0x0000000000008082u64,
    0x800000000000808au64,
    0x8000000080008000u64,
    0x000000000000808bu64,
    0x0000000080000001u64,
    0x8000000080008081u64,
    0x8000000000008009u64,
    0x000000000000008au64,
    0x0000000000000088u64,
    0x0000000080008009u64,
    0x000000008000000au64,
    0x000000008000808bu64,
    0x800000000000008bu64,
    0x8000000000008089u64,
    0x8000000000008003u64,
    0x8000000000008002u64,
    0x8000000000000080u64,
    0x000000000000800au64,
    0x800000008000000au64,
    0x8000000080008081u64,
    0x8000000000008080u64,
    0x0000000080000001u64,
    0x8000000080008008u64,
];

#[inline(always)]
fn lane_memory_barrier(lanes: &mut [u64]) {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64"
    ))]
    unsafe {
        // The empty assembly has an implicit memory clobber. It makes each
        // protected array observable without turning every lane operation into
        // a volatile access.
        core::arch::asm!(
            "/* {lanes} */",
            lanes = in(reg) lanes.as_mut_ptr(),
            options(nostack)
        );
    }

    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64"
    )))]
    {
        // Portable fallback for targets without stable inline assembly (for
        // example wasm32). Zeroize uses the same compiler-fence primitive to
        // keep its final wipe from moving across surrounding memory accesses.
        let _ = core::hint::black_box(lanes.as_mut_ptr());
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[inline(never)]
fn keccak_theta(state: &mut [u64; 25], workspace: &mut [u64; 7]) {
    for x in 0..5 {
        workspace[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    lane_memory_barrier(workspace);

    for x in 0..5 {
        let theta = workspace[(x + 4) % 5] ^ workspace[(x + 1) % 5].rotate_left(1);
        for y in 0..5 {
            state[x + 5 * y] ^= theta;
        }
    }
    lane_memory_barrier(state);
}

#[inline(never)]
fn keccak_rho_pi(state: &mut [u64; 25], workspace: &mut [u64; 7]) {
    workspace[5] = state[1];
    lane_memory_barrier(workspace);

    macro_rules! move_lane {
        ($destination:expr, $rotation:expr) => {{
            workspace[6] = state[$destination];
            state[$destination] = workspace[5].rotate_left($rotation);
            workspace[5] = workspace[6];
        }};
    }

    move_lane!(10, 1);
    move_lane!(7, 3);
    move_lane!(11, 6);
    move_lane!(17, 10);
    move_lane!(18, 15);
    move_lane!(3, 21);
    move_lane!(5, 28);
    move_lane!(16, 36);
    move_lane!(8, 45);
    move_lane!(21, 55);
    move_lane!(24, 2);
    move_lane!(4, 14);
    move_lane!(15, 27);
    move_lane!(23, 41);
    move_lane!(19, 56);
    move_lane!(13, 8);
    move_lane!(12, 25);
    move_lane!(2, 43);
    move_lane!(20, 62);
    move_lane!(14, 18);
    move_lane!(22, 39);
    move_lane!(9, 61);
    move_lane!(6, 20);
    move_lane!(1, 44);

    lane_memory_barrier(state);
    lane_memory_barrier(workspace);
}

#[inline(never)]
fn keccak_chi(state: &mut [u64; 25], workspace: &mut [u64; 7]) {
    macro_rules! mix_row {
        ($row:expr) => {{
            workspace[0] = state[$row];
            workspace[1] = state[$row + 1];
            workspace[2] = state[$row + 2];
            workspace[3] = state[$row + 3];
            workspace[4] = state[$row + 4];
            lane_memory_barrier(workspace);

            state[$row] = workspace[0] ^ ((!workspace[1]) & workspace[2]);
            state[$row + 1] = workspace[1] ^ ((!workspace[2]) & workspace[3]);
            state[$row + 2] = workspace[2] ^ ((!workspace[3]) & workspace[4]);
            state[$row + 3] = workspace[3] ^ ((!workspace[4]) & workspace[0]);
            state[$row + 4] = workspace[4] ^ ((!workspace[0]) & workspace[1]);
        }};
    }

    mix_row!(0);
    mix_row!(5);
    mix_row!(10);
    mix_row!(15);
    mix_row!(20);

    lane_memory_barrier(state);
}

#[inline(never)]
fn keccak_f1600_state_permute(state: &mut [u64]) {
    assert!(state.len() >= 25);
    let state: &mut [u64; 25] = (&mut state[..25]).try_into().unwrap();
    let mut workspace = Zeroizing::new([0u64; 7]);

    for &round_constant in KECCAK_F_ROUND_CONSTANTS.iter() {
        keccak_theta(state, &mut *workspace);
        keccak_rho_pi(state, &mut *workspace);
        keccak_chi(state, &mut *workspace);
        state[0] ^= round_constant;
        lane_memory_barrier(state);
    }
}

fn keccak_absorb(s: &mut [u64], r: usize, m: &[u8], mut mlen: u64, p: u8) {
    let mut t = Zeroizing::new([0u8; 200]);
    let mut remaining = m;

    while mlen >= r as u64 {
        for i in 0..(r / 8) {
            s[i] ^= load64(&remaining[(8 * i)..]);
        }
        keccak_f1600_state_permute(s);
        mlen -= r as u64;
        remaining = &remaining[r..];
    }

    for i in 0..r {
        t[i as usize] = 0;
    }

    for i in 0..mlen {
        t[i as usize] = remaining[i as usize];
    }

    t[mlen as usize] = p;
    t[(r - 1) as usize] |= 128;
    for i in 0..(r / 8) {
        s[i as usize] ^= load64(t.get(8 * i as usize..t.len()).unwrap());
    }
}

fn keccak_squeezeblocks(mut h: &mut [u8], mut nblocks: usize, s: &mut [u64], r: usize) {
    while nblocks > 0 {
        keccak_f1600_state_permute(s);
        let h_length = h.len();
        for i in 0..(r >> 3) {
            store64(&mut h[(8 * i as usize)..h_length], s[i as usize]);
        }
        h = &mut h[r as usize..h_length];
        nblocks -= 1;
    }
}

pub fn shake128(mut output: &mut [u8], outlen: usize, input: &[u8], inlen: u64) {
    let Ok(input_length) = usize::try_from(inlen) else {
        output.fill(0);
        return;
    };
    if outlen > output.len() || input_length > input.len() {
        output.fill(0);
        return;
    }
    let mut s = Zeroizing::new([0u64; 25]);
    let mut d = Zeroizing::new([0u8; SHAKE128_RATE]);

    for i in 0..25 {
        s[i] = 0;
    }
    keccak_absorb(&mut *s, SHAKE128_RATE, input, inlen, 0x1F);

    keccak_squeezeblocks(output, outlen / SHAKE128_RATE, &mut *s, SHAKE128_RATE);
    let out_length = output.len();
    output = output
        .get_mut((outlen / SHAKE128_RATE) * SHAKE128_RATE..out_length)
        .unwrap();

    if (outlen % SHAKE128_RATE) > 0 {
        keccak_squeezeblocks(&mut *d, 1, &mut *s, SHAKE128_RATE);
        for i in 0..outlen % SHAKE128_RATE {
            output[i] = d[i];
        }
    }
}

pub fn shake256(mut output: &mut [u8], outlen: usize, input: &[u8], inlen: u64) {
    let Ok(input_length) = usize::try_from(inlen) else {
        output.fill(0);
        return;
    };
    if outlen > output.len() || input_length > input.len() {
        output.fill(0);
        return;
    }
    let mut s = Zeroizing::new([0u64; 25]);
    let mut d = Zeroizing::new([0u8; SHAKE256_RATE]);

    for i in 0..25 {
        s[i] = 0;
    }
    keccak_absorb(&mut *s, SHAKE256_RATE, input, inlen, 0x1F);

    keccak_squeezeblocks(output, outlen / SHAKE256_RATE, &mut *s, SHAKE256_RATE);
    let out_length = output.len();
    output = &mut output[(outlen / SHAKE256_RATE) * SHAKE256_RATE..out_length];

    if (outlen % SHAKE256_RATE) > 0 {
        keccak_squeezeblocks(&mut *d, 1, &mut *s, SHAKE256_RATE);
        for i in 0..outlen % SHAKE256_RATE {
            output[i] = d[i];
        }
    }
}
