// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.
use zeroize::Zeroizing;

const BLOCK_SIZE: usize = 64;
const LENGTH_SIZE: usize = 8;

const INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn secret_memory_barrier<T>(memory: &mut [T]) {
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64"
    ))]
    unsafe {
        // The compiler must treat the pointed-to memory as observable here.
        // This keeps the protected arrays materialized around the split
        // schedule and round helpers without making every access volatile.
        core::arch::asm!(
            "/* {memory} */",
            memory = in(reg) memory.as_mut_ptr(),
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
        let _ = core::hint::black_box(memory.as_mut_ptr());
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

#[inline(never)]
fn copy_remainder(remainder: &[u8], tail: &mut [u8; BLOCK_SIZE]) {
    for (index, byte) in remainder.iter().copied().enumerate() {
        // Volatile stores keep the compiler from replacing this bounded copy
        // with a library memcpy whose private stack use is outside our audit.
        unsafe { core::ptr::write_volatile(tail.as_mut_ptr().add(index), byte) };
    }
    secret_memory_barrier(tail);
}

#[inline(never)]
fn prepare_schedule(block: &[u8; BLOCK_SIZE], schedule: &mut [u32; 64]) {
    for (word, bytes) in schedule[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }

    for index in 16..64 {
        let previous_15 = schedule[index - 15];
        let sigma_0 =
            previous_15.rotate_right(7) ^ previous_15.rotate_right(18) ^ (previous_15 >> 3);
        let previous_2 = schedule[index - 2];
        let sigma_1 =
            previous_2.rotate_right(17) ^ previous_2.rotate_right(19) ^ (previous_2 >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(sigma_0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(sigma_1);
    }

    secret_memory_barrier(schedule);
}

#[inline(never)]
fn sha256_round(work: &mut [u32; 8], round_word: u32) {
    let sigma_1 = work[4].rotate_right(6) ^ work[4].rotate_right(11) ^ work[4].rotate_right(25);
    let choice = (work[4] & work[5]) ^ ((!work[4]) & work[6]);
    let temp_1 = work[7]
        .wrapping_add(sigma_1)
        .wrapping_add(choice)
        .wrapping_add(round_word);
    let sigma_0 = work[0].rotate_right(2) ^ work[0].rotate_right(13) ^ work[0].rotate_right(22);
    let majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
    let temp_2 = sigma_0.wrapping_add(majority);

    work[7] = work[6];
    work[6] = work[5];
    work[5] = work[4];
    work[4] = work[3].wrapping_add(temp_1);
    work[3] = work[2];
    work[2] = work[1];
    work[1] = work[0];
    work[0] = temp_1.wrapping_add(temp_2);
    secret_memory_barrier(work);
}

#[inline(never)]
fn compress(
    block: &[u8; BLOCK_SIZE],
    state: &mut [u32; 8],
    schedule: &mut [u32; 64],
    work: &mut [u32; 8],
) {
    prepare_schedule(block, schedule);
    work.copy_from_slice(state);
    secret_memory_barrier(work);

    for round in 0..64 {
        sha256_round(work, schedule[round].wrapping_add(ROUND_CONSTANTS[round]));
    }

    for index in 0..8 {
        state[index] = state[index].wrapping_add(work[index]);
    }
    secret_memory_barrier(state);
}

pub fn sha2_256(input: &Vec<u8>) -> Vec<u8> {
    // SHA-256 encodes the message length in a 64-bit bit count. Validate it
    // before any input-derived state is created.
    let input_length = u64::try_from(input.len()).expect("SHA-256 input is too long");
    let bit_length = input_length
        .checked_mul(8)
        .expect("SHA-256 input is too long");

    // Allocate the returned object before handling the input. Allocation
    // failure therefore cannot strand a newly-created secret workspace.
    let mut output = vec![0u8; 32];
    let mut state = Zeroizing::new(INITIAL_STATE);
    let mut schedule = Zeroizing::new([0u32; 64]);
    let mut work = Zeroizing::new([0u32; 8]);
    let mut tail = Zeroizing::new([0u8; BLOCK_SIZE]);

    let mut blocks = input.chunks_exact(BLOCK_SIZE);
    for block in &mut blocks {
        let block: &[u8; BLOCK_SIZE] = block
            .try_into()
            .expect("chunks_exact returned a partial SHA-256 block");
        compress(block, &mut state, &mut schedule, &mut work);
    }

    let remainder = blocks.remainder();
    copy_remainder(remainder, &mut tail);
    tail[remainder.len()] = 0x80;

    if remainder.len() >= BLOCK_SIZE - LENGTH_SIZE {
        compress(&tail, &mut state, &mut schedule, &mut work);
        tail.fill(0);
    }

    for index in 0..LENGTH_SIZE {
        tail[BLOCK_SIZE - LENGTH_SIZE + index] =
            (bit_length >> (8 * (LENGTH_SIZE - 1 - index))) as u8;
    }
    compress(&tail, &mut state, &mut schedule, &mut work);

    for (word_index, word) in state.iter().enumerate() {
        for byte_index in 0..4 {
            output[word_index * 4 + byte_index] = (word >> (8 * (3 - byte_index))) as u8;
        }
    }

    output
}
