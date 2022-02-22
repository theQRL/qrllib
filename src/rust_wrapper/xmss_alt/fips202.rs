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

fn rol(a: u64, offset: i32) -> u64 {
    ((a) << (offset)) ^ ((a) >> (64 - (offset)))
}
fn load64(x: &[u8]) -> u64 {
    let mut r: u64 = 0;

    for i in 0..8 {
        r |= (x[i] << 8 * i) as u64;
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

fn keccak_f1600_state_permute(state: &mut [u64]) {
    let (mut Aba, mut Abe, mut Abi, mut Abo, mut Abu): (u64, u64, u64, u64, u64);
    let (mut Aga, mut Age, mut Agi, mut Ago, mut Agu): (u64, u64, u64, u64, u64);
    let (mut Aka, mut Ake, mut Aki, mut Ako, mut Aku): (u64, u64, u64, u64, u64);
    let (mut Ama, mut Ame, mut Ami, mut Amo, mut Amu): (u64, u64, u64, u64, u64);
    let (mut Asa, mut Ase, mut Asi, mut Aso, mut Asu): (u64, u64, u64, u64, u64);
    let (mut BCa, mut BCe, mut BCi, mut BCo, mut BCu): (u64, u64, u64, u64, u64);
    let (mut Da, mut De, mut Di, mut Do, mut Du): (u64, u64, u64, u64, u64);
    let (mut Eba, mut Ebe, mut Ebi, mut Ebo, mut Ebu): (u64, u64, u64, u64, u64);
    let (mut Ega, mut Ege, mut Egi, mut Ego, mut Egu): (u64, u64, u64, u64, u64);
    let (mut Eka, mut Eke, mut Eki, mut Eko, mut Eku): (u64, u64, u64, u64, u64);
    let (mut Ema, mut Eme, mut Emi, mut Emo, mut Emu): (u64, u64, u64, u64, u64);
    let (mut Esa, mut Ese, mut Esi, mut Eso, mut Esu): (u64, u64, u64, u64, u64);

    //copyFromState(A, state)
    Aba = state[0];
    Abe = state[1];
    Abi = state[2];
    Abo = state[3];
    Abu = state[4];
    Aga = state[5];
    Age = state[6];
    Agi = state[7];
    Ago = state[8];
    Agu = state[9];
    Aka = state[10];
    Ake = state[11];
    Aki = state[12];
    Ako = state[13];
    Aku = state[14];
    Ama = state[15];
    Ame = state[16];
    Ami = state[17];
    Amo = state[18];
    Amu = state[19];
    Asa = state[20];
    Ase = state[21];
    Asi = state[22];
    Aso = state[23];
    Asu = state[24];

    for round in (0..NROUNDS).step_by(2) {
        //    prepareTheta
        BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
        Da = BCu ^ rol(BCe, 1);
        De = BCa ^ rol(BCi, 1);
        Di = BCe ^ rol(BCo, 1);
        Do = BCi ^ rol(BCu, 1);
        Du = BCo ^ rol(BCa, 1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = rol(Age, 44);
        Aki ^= Di;
        BCi = rol(Aki, 43);
        Amo ^= Do;
        BCo = rol(Amo, 21);
        Asu ^= Du;
        BCu = rol(Asu, 14);
        Eba = BCa ^ ((!BCe) & BCi);
        Eba ^= KECCAK_F_ROUND_CONSTANTS[round as usize];
        Ebe = BCe ^ ((!BCi) & BCo);
        Ebi = BCi ^ ((!BCo) & BCu);
        Ebo = BCo ^ ((!BCu) & BCa);
        Ebu = BCu ^ ((!BCa) & BCe);

        Abo ^= Do;
        BCa = rol(Abo, 28);
        Agu ^= Du;
        BCe = rol(Agu, 20);
        Aka ^= Da;
        BCi = rol(Aka, 3);
        Ame ^= De;
        BCo = rol(Ame, 45);
        Asi ^= Di;
        BCu = rol(Asi, 61);
        Ega = BCa ^ ((!BCe) & BCi);
        Ege = BCe ^ ((!BCi) & BCo);
        Egi = BCi ^ ((!BCo) & BCu);
        Ego = BCo ^ ((!BCu) & BCa);
        Egu = BCu ^ ((!BCa) & BCe);

        Abe ^= De;
        BCa = rol(Abe, 1);
        Agi ^= Di;
        BCe = rol(Agi, 6);
        Ako ^= Do;
        BCi = rol(Ako, 25);
        Amu ^= Du;
        BCo = rol(Amu, 8);
        Asa ^= Da;
        BCu = rol(Asa, 18);
        Eka = BCa ^ ((!BCe) & BCi);
        Eke = BCe ^ ((!BCi) & BCo);
        Eki = BCi ^ ((!BCo) & BCu);
        Eko = BCo ^ ((!BCu) & BCa);
        Eku = BCu ^ ((!BCa) & BCe);

        Abu ^= Du;
        BCa = rol(Abu, 27);
        Aga ^= Da;
        BCe = rol(Aga, 36);
        Ake ^= De;
        BCi = rol(Ake, 10);
        Ami ^= Di;
        BCo = rol(Ami, 15);
        Aso ^= Do;
        BCu = rol(Aso, 56);
        Ema = BCa ^ ((!BCe) & BCi);
        Eme = BCe ^ ((!BCi) & BCo);
        Emi = BCi ^ ((!BCo) & BCu);
        Emo = BCo ^ ((!BCu) & BCa);
        Emu = BCu ^ ((!BCa) & BCe);

        Abi ^= Di;
        BCa = rol(Abi, 62);
        Ago ^= Do;
        BCe = rol(Ago, 55);
        Aku ^= Du;
        BCi = rol(Aku, 39);
        Ama ^= Da;
        BCo = rol(Ama, 41);
        Ase ^= De;
        BCu = rol(Ase, 2);
        Esa = BCa ^ ((!BCe) & BCi);
        Ese = BCe ^ ((!BCi) & BCo);
        Esi = BCi ^ ((!BCo) & BCu);
        Eso = BCo ^ ((!BCu) & BCa);
        Esu = BCu ^ ((!BCa) & BCe);

        //    prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        Da = BCu ^ rol(BCe, 1);
        De = BCa ^ rol(BCi, 1);
        Di = BCe ^ rol(BCo, 1);
        Do = BCi ^ rol(BCu, 1);
        Du = BCo ^ rol(BCa, 1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = rol(Ege, 44);
        Eki ^= Di;
        BCi = rol(Eki, 43);
        Emo ^= Do;
        BCo = rol(Emo, 21);
        Esu ^= Du;
        BCu = rol(Esu, 14);
        Aba = BCa ^ ((!BCe) & BCi);
        Aba ^= KECCAK_F_ROUND_CONSTANTS[(round + 1) as usize];
        Abe = BCe ^ ((!BCi) & BCo);
        Abi = BCi ^ ((!BCo) & BCu);
        Abo = BCo ^ ((!BCu) & BCa);
        Abu = BCu ^ ((!BCa) & BCe);

        Ebo ^= Do;
        BCa = rol(Ebo, 28);
        Egu ^= Du;
        BCe = rol(Egu, 20);
        Eka ^= Da;
        BCi = rol(Eka, 3);
        Eme ^= De;
        BCo = rol(Eme, 45);
        Esi ^= Di;
        BCu = rol(Esi, 61);
        Aga = BCa ^ ((!BCe) & BCi);
        Age = BCe ^ ((!BCi) & BCo);
        Agi = BCi ^ ((!BCo) & BCu);
        Ago = BCo ^ ((!BCu) & BCa);
        Agu = BCu ^ ((!BCa) & BCe);

        Ebe ^= De;
        BCa = rol(Ebe, 1);
        Egi ^= Di;
        BCe = rol(Egi, 6);
        Eko ^= Do;
        BCi = rol(Eko, 25);
        Emu ^= Du;
        BCo = rol(Emu, 8);
        Esa ^= Da;
        BCu = rol(Esa, 18);
        Aka = BCa ^ ((!BCe) & BCi);
        Ake = BCe ^ ((!BCi) & BCo);
        Aki = BCi ^ ((!BCo) & BCu);
        Ako = BCo ^ ((!BCu) & BCa);
        Aku = BCu ^ ((!BCa) & BCe);

        Ebu ^= Du;
        BCa = rol(Ebu, 27);
        Ega ^= Da;
        BCe = rol(Ega, 36);
        Eke ^= De;
        BCi = rol(Eke, 10);
        Emi ^= Di;
        BCo = rol(Emi, 15);
        Eso ^= Do;
        BCu = rol(Eso, 56);
        Ama = BCa ^ ((!BCe) & BCi);
        Ame = BCe ^ ((!BCi) & BCo);
        Ami = BCi ^ ((!BCo) & BCu);
        Amo = BCo ^ ((!BCu) & BCa);
        Amu = BCu ^ ((!BCa) & BCe);

        Ebi ^= Di;
        BCa = rol(Ebi, 62);
        Ego ^= Do;
        BCe = rol(Ego, 55);
        Eku ^= Du;
        BCi = rol(Eku, 39);
        Ema ^= Da;
        BCo = rol(Ema, 41);
        Ese ^= De;
        BCu = rol(Ese, 2);
        Asa = BCa ^ ((!BCe) & BCi);
        Ase = BCe ^ ((!BCi) & BCo);
        Asi = BCi ^ ((!BCo) & BCu);
        Aso = BCo ^ ((!BCu) & BCa);
        Asu = BCu ^ ((!BCa) & BCe);
    }

    //copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

fn keccak_absorb(s: &mut [u64], r: usize, m: &[u8], mut mlen: u64, p: u8) {
    let t = &mut [0; 200];
    let mut m_clone: &[u8] = m.clone();

    while mlen >= r as u64 {
        for i in 0..(r / 8) {
            s[i as usize] ^= load64(&m_clone[(8 * i as usize)..m_clone.len()]);
        }
        keccak_f1600_state_permute(s);
        mlen -= r as u64;
        m_clone = &m_clone[r as usize..m.len()];
    }

    for i in 0..r {
        t[i as usize] = 0;
    }

    for i in 0..mlen {
        t[i as usize] = m[i as usize];
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
    let mut s: [u64; 25] = [0; 25];
    let mut d: [u8; SHAKE128_RATE] = [0; SHAKE128_RATE];

    for i in 0..25 {
        s[i] = 0;
    }
    keccak_absorb(&mut s, SHAKE128_RATE, input, inlen, 0x1F);

    keccak_squeezeblocks(output, outlen / SHAKE128_RATE, &mut s, SHAKE128_RATE);
    let out_length = output.len();
    output = &mut output[(outlen / SHAKE128_RATE) * SHAKE128_RATE..out_length];

    if (outlen % SHAKE128_RATE) > 0 {
        keccak_squeezeblocks(&mut d, 1, &mut s, SHAKE128_RATE);
        for i in 0..outlen % SHAKE128_RATE {
            output[i] = d[i];
        }
    }
}

fn shake256(mut output: &mut [u8], outlen: usize, input: &[u8], inlen: u64) {
    let mut s: [u64; 25] = [0; 25];
    let mut d: [u8; SHAKE256_RATE] = [0; SHAKE256_RATE];

    for i in 0..25 {
        s[i] = 0;
    }
    keccak_absorb(&mut s, SHAKE256_RATE, input, inlen, 0x1F);

    keccak_squeezeblocks(output, outlen / SHAKE256_RATE, &mut s, SHAKE256_RATE);
    let out_length = output.len();
    output = &mut output[(outlen / SHAKE256_RATE) * SHAKE256_RATE..out_length];

    if (outlen % SHAKE256_RATE) > 0 {
        keccak_squeezeblocks(&mut d, 1, &mut s, SHAKE256_RATE);
        for i in 0..outlen % SHAKE256_RATE {
            output[i] = d[i];
        }
    }
}
