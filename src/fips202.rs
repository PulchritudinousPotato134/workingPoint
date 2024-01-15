/* Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer
 * and the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe 
 * Converted to Rust by Adam B */

 pub mod fips202{
     use crate::xof_state::XofAbsorb;


     pub fn test()
    {
        println!("test");
    }
     const NROUNDS: usize = 24;
 pub fn rol(a: u64, offset: u32) -> u64 {
    (a << offset) | (a >> (64 - offset))
}
 /*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into uint64_t in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
 fn load64(x: &[u8]) -> u64 {
    let mut r = 0u64;
    for (i, &byte) in x.iter().enumerate() {
        let shifted = (byte as u64).wrapping_shl(8 * i as u32);
        r |= shifted;
    }
    r
}
 /*************************************************
 * Name:        store64
 *
 * Description: Store a 64-bit integer to array of 8 bytes in little-endian order
 *
 * Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
 *              - uint64_t u: input 64-bit unsigned integer
 **************************************************/
 pub fn store64(x: &mut [u8], u: u64) {
    for i in 0..8 {
        x[i] = (u >> (8 * i)) as u8;
    }
}
 /* Keccak round constants */
 pub static KECCAKF_ROUND_CONSTANTS: [u64; NROUNDS] = [
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
 
 /*************************************************
 * Name:        keccak_f1600_state_permute
 *
 * Description: The Keccak F1600 Permutation
 *
 * Arguments:   - uint64_t *state: pointer to input/output Keccak state
 **************************************************/

     //this is the replacement for the ROL macro
     fn ROL(a: u64, offset: u32) -> u64 {
         (a << offset) | (a >> (64 - offset))
     }


     pub fn keccak_f1600_state_permute(state: &mut [u64; 25]) {

     let (mut aba, mut abe, mut abi, mut abo, mut abu): (u64, u64, u64, u64, u64);
     let (mut aga, mut age, mut agi, mut ago, mut agu): (u64, u64, u64, u64, u64);
     let (mut aka, mut ake, mut aki, mut ako, mut aku): (u64, u64, u64, u64, u64);
     let (mut ama, mut ame, mut ami, mut amo, mut amu): (u64, u64, u64, u64, u64);
     let (mut asa, mut ase, mut asi, mut aso, mut asu): (u64, u64, u64, u64, u64);
     let (mut bca, mut bce, mut bci, mut bco, mut bcu): (u64, u64, u64, u64, u64);
     let (mut da, mut de, mut di, mut r#do, mut du): (u64, u64, u64, u64, u64);
     let (mut eba, mut ebe, mut ebi, mut ebo, mut ebu): (u64, u64, u64, u64, u64);
     let (mut ega, mut ege, mut egi, mut ego, mut egu): (u64, u64, u64, u64, u64);
     let (mut eka, mut eke, mut eki, mut eko, mut eku): (u64, u64, u64, u64, u64);
     let (mut ema, mut eme, mut emi, mut emo, mut emu): (u64, u64, u64, u64, u64);
     let (mut esa, mut ese, mut esi, mut eso, mut esu): (u64, u64, u64, u64, u64);


     // Copy state to temporary variables
    aba = state[0];
    abe = state[1];
    abi = state[2];
    abo = state[3];
    abu = state[4];
    aga = state[5];
    age = state[6];
    agi = state[7];
    ago = state[8];
    agu = state[9];
    aka = state[10];
    ake = state[11];
    aki = state[12];
    ako = state[13];
    aku = state[14];
    ama = state[15];
    ame = state[16];
    ami = state[17];
    amo = state[18];
    amu = state[19];
    asa = state[20];
    ase = state[21];
    asi = state[22];
    aso = state[23];
    asu = state[24];
 
        for round in (0..NROUNDS).step_by(2) 
         {
             //    prepareTheta
             bca = aba ^ aga ^ aka ^ ama ^ asa;
             bce = abe ^ age ^ ake ^ ame ^ ase;
             bci = abi ^ agi ^ aki ^ ami ^ asi;
             bco = abo ^ ago ^ ako ^ amo ^ aso;
             bcu = abu ^ agu ^ aku ^ amu ^ asu;
 
             //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
             da = bcu ^ROL(bce, 1);
             de = bca ^ROL(bci, 1);
             di = bce ^ROL(bco, 1);
             r#do = bci ^ROL(bcu, 1);
             du = bco ^ROL(bca, 1);
 
             aba ^= da;
             bca = aba;
             age ^= de;
             bce = ROL(age, 44);
             aki ^= di;
             bci = ROL(aki, 43);
             amo ^= r#do;
             bco = ROL(amo, 21);
             asu ^= du;
             bcu = ROL(asu, 14);
             eba = bca ^ ((!bce) & bci);
             eba ^= KECCAKF_ROUND_CONSTANTS[round];
             ebe =   bce ^((!bci)& bco);
             ebi =   bci ^((!bco)& bcu);
             ebo =   bco ^((!bcu)& bca);
             ebu =   bcu ^((!bca)& bce);
 
             abo ^= r#do;
             bca = ROL(abo, 28);
             agu ^= du;
             bce = ROL(agu, 20);
             aka ^= da;
             bci = ROL(aka, 3);
             ame ^= de;
             bco = ROL(ame, 45);
             asi ^= di;
             bcu = ROL(asi, 61);
             ega =   bca ^((!bce)& bci);
             ege =   bce ^((!bci)& bco);
             egi =   bci ^((!bco)& bcu);
             ego =   bco ^((!bcu)& bca);
             egu =   bcu ^((!bca)& bce);
 
             abe ^= de;
             bca = ROL(abe, 1);
             agi ^= di;
             bce = ROL(agi, 6);
             ako ^= r#do;
             bci = ROL(ako, 25);
             amu ^= du;
             bco = ROL(amu, 8);
             asa ^= da;
             bcu = ROL(asa, 18);
             eka =   bca ^((!bce)& bci);
             eke =   bce ^((!bci)& bco);
             eki =   bci ^((!bco)& bcu);
             eko =   bco ^((!bcu)& bca);
             eku =   bcu ^((!bca)& bce);
 
             abu ^= du;
             bca = ROL(abu, 27);
             aga ^= da;
             bce = ROL(aga, 36);
             ake ^= de;
             bci = ROL(ake, 10);
             ami ^= di;
             bco = ROL(ami, 15);
             aso ^= r#do;
             bcu = ROL(aso, 56);
             ema =   bca ^((!bce)& bci);
             eme =   bce ^((!bci)& bco);
             emi =   bci ^((!bco)& bcu);
             emo =   bco ^((!bcu)& bca);
             emu =   bcu ^((!bca)& bce);
 
             abi ^= di;
             bca = ROL(abi, 62);
             ago ^= r#do;
             bce = ROL(ago, 55);
             aku ^= du;
             bci = ROL(aku, 39);
             ama ^= da;
             bco = ROL(ama, 41);
             ase ^= de;
             bcu = ROL(ase, 2);
             esa =   bca ^((!bce)& bci);
             ese =   bce ^((!bci)& bco);
             esi =   bci ^((!bco)& bcu);
             eso =   bco ^((!bcu)& bca);
             esu =   bcu ^((!bca)& bce);
 
             //    prepareTheta
             bca = eba ^ ega ^ eka ^ ema ^ esa;
             bce = ebe ^ ege ^ eke ^ eme ^ ese;
             bci = ebi ^ egi ^ eki ^ emi ^ esi;
             bco = ebo ^ ego ^ eko ^ emo ^ eso;
             bcu = ebu ^ egu ^ eku ^ emu ^ esu;
 
             //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
             da = bcu ^ROL(bce, 1);
             de = bca ^ROL(bci, 1);
             di = bce ^ROL(bco, 1);
             r#do = bci ^ROL(bcu, 1);
             du = bco ^ROL(bca, 1);
 
             eba ^= da;
             bca = eba;
             ege ^= de;
             bce = ROL(ege, 44);
             eki ^= di;
             bci = ROL(eki, 43);
             emo ^= r#do;
             bco = ROL(emo, 21);
             esu ^= du;
             bcu = ROL(esu, 14);
             aba =   bca ^((!bce)& bci);
             aba ^= KECCAKF_ROUND_CONSTANTS[round +1];
             abe =   bce ^((!bci)& bco);
             abi =   bci ^((!bco)& bcu);
             abo =   bco ^((!bcu)& bca);
             abu =   bcu ^((!bca)& bce);
 
             ebo ^= r#do;
             bca = ROL(ebo, 28);
             egu ^= du;
             bce = ROL(egu, 20);
             eka ^= da;
             bci = ROL(eka, 3);
             eme ^= de;
             bco = ROL(eme, 45);
             esi ^= di;
             bcu = ROL(esi, 61);
             aga =   bca ^((!bce)& bci);
             age =   bce ^((!bci)& bco);
             agi =   bci ^((!bco)& bcu);
             ago =   bco ^((!bcu)& bca);
             agu =   bcu ^((!bca)& bce);
 
             ebe ^= de;
             bca = ROL(ebe, 1);
             egi ^= di;
             bce = ROL(egi, 6);
             eko ^= r#do;
             bci = ROL(eko, 25);
             emu ^= du;
             bco = ROL(emu, 8);
             esa ^= da;
             bcu = ROL(esa, 18);
             aka =   bca ^((!bce)& bci);
             ake =   bce ^((!bci)& bco);
             aki =   bci ^((!bco)& bcu);
             ako =   bco ^((!bcu)& bca);
             aku =   bcu ^((!bca)& bce);
 
             ebu ^= du;
             bca = ROL(ebu, 27);
             ega ^= da;
             bce = ROL(ega, 36);
             eke ^= de;
             bci = ROL(eke, 10);
             emi ^= di;
             bco = ROL(emi, 15);
             eso ^= r#do;
             bcu = ROL(eso, 56);
             ama =   bca ^((!bce)& bci);
             ame =   bce ^((!bci)& bco);
             ami =   bci ^((!bco)& bcu);
             amo =   bco ^((!bcu)& bca);
             amu =   bcu ^((!bca)& bce);
 
             ebi ^= di;
             bca = ROL(ebi, 62);
             ego ^= r#do;
             bce = ROL(ego, 55);
             eku ^= du;
             bci = ROL(eku, 39);
             ema ^= da;
             bco = ROL(ema, 41);
             ese ^= de;
             bcu = ROL(ese, 2);
             asa =   bca ^((!bce)& bci);
             ase =   bce ^((!bci)& bco);
             asi =   bci ^((!bco)& bcu);
             aso =   bco ^((!bcu)& bca);
             asu =   bcu ^((!bca)& bce);

         }
 
         //copyToState(state, A)
         state[ 0] = aba;
         state[ 1] = abe;
         state[ 2] = abi;
         state[ 3] = abo;
         state[ 4] = abu;
         state[ 5] = aga;
         state[ 6] = age;
         state[ 7] = agi;
         state[ 8] = ago;
         state[ 9] = agu;
         state[10] = aka;
         state[11] = ake;
         state[12] = aki;
         state[13] = ako;
         state[14] = aku;
         state[15] = ama;
         state[16] = ame;
         state[17] = ami;
         state[18] = amo;
         state[19] = amu;
         state[20] = asa;
         state[21] = ase;
         state[22] = asi;
         state[23] = aso;
         state[24] = asu;
 }
 
 /*************************************************
 * Name:        keccak_absorb
 *
 * Description: Absorb step of Keccak;
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 *              - const uint8_t *m: pointer to input to be absorbed into s
 *              - size_t mlen: length of input in bytes
 *              - uint8_t p: domain-separation byte for different
 *                           Keccak-derived functions
 **************************************************/
 fn keccak_absorb(s: &mut [u64; 25], r: usize, m: &[u8], mut mlen: usize, p: u8) {
    // Zero State
    s.fill(0);

    let mut idx = 0usize;
    while mlen >= r {
        for i in 0..(r / 8) {
            s[i] ^= load64(&m[idx + 8 * i..idx + 8 * (i + 1)]);

        }
        idx += r;
        mlen -= r;
        keccak_f1600_state_permute(s);
    }

    for i in 0..mlen {
        s[i / 8] ^= (m[idx + i] as u64) << 8 * (i % 8);
    }
    s[mlen / 8] ^= (p as u64) << 8 * (mlen % 8);
    s[(r - 1) / 8] ^= 1u64 << 63;
}



 /*************************************************
 * Name:        keccak_squeezeblocks
 *
 * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
 *              Modifies the state. Can be called multiple times to keep
 *              squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *h: pointer to output blocks
 *              - size_t nblocks: number of blocks to be squeezed (written to h)
 *              - uint64_t *s: pointer to input/output Keccak state
 *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
 **************************************************/
     pub fn keccak_squeezeblocks(out: &mut [u8], mut nblocks: usize, s: &mut [u64; 25], r: usize) {
         let mut i = 0;
         let mut out_index = 0;

         while nblocks > 0 {
             keccak_f1600_state_permute(s);
             for j in 0..(r / 8) {
                 store64(&mut out[out_index..(out_index + 8)], s[j]);
                 out_index += 8;
             }
             nblocks -= 1;
             i += 1;
         }
     }

 /*************************************************
 * Name:        shake128_absorb
 *
 * Description: Absorb step of the SHAKE128 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - keccak_state *state: pointer to (uninitialized) output
 *                                     Keccak state
 *              - const uint8_t *in:   pointer to input to be absorbed into s
 *              - size_t inlen:        length of input in bytes
 **************************************************/
     //shake182 rate = 168;
 pub fn shake128_absorb(state: &mut crate::xof_state::KeccakState, in_data: &[u8]) {
    keccak_absorb(&mut state.s, 168, in_data, in_data.len(), 0x1F);
}
 
 /*************************************************
 * Name:        shake128_squeezeblocks
 *
 * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
 *              SHAKE128_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *out:    pointer to output blocks
 *              - size_t nblocks:  number of blocks to be squeezed
 *                                 (written to output)
 *              - keccak_state *s: pointer to input/output Keccak state
 **************************************************/
 pub fn shake128_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut crate::xof_state::KeccakState) {
    keccak_squeezeblocks(out, nblocks, &mut state.s, 168);
}

 
 /*************************************************
 * Name:        shake256_absorb
 *
 * Description: Absorb step of the SHAKE256 XOF.
 *              non-incremental, starts by zeroeing the state.
 *
 * Arguments:   - keccak_state *s:   pointer to (uninitialized) output Keccak state
 *              - const uint8_t *in: pointer to input to be absorbed into s
 *              - size_t inlen:      length of input in bytes
 **************************************************/
     //shake256 rate is 136
 pub fn shake256_absorb(state: &mut [u64; 25], in_data: &[u8]) {
    keccak_absorb(state, 136, in_data, in_data.len(), 0x1F);
}
 
 /*************************************************
 * Name:        shake256_squeezeblocks
 *
 * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
 *              SHAKE256_RATE bytes each. Modifies the state. Can be called
 *              multiple times to keep squeezing, i.e., is incremental.
 *
 * Arguments:   - uint8_t *out:    pointer to output blocks
 *              - size_t nblocks:  number of blocks to be squeezed
 *                                 (written to output)
 *              - keccak_State *s: pointer to input/output Keccak state
 **************************************************/
 pub fn shake256_squeezeblocks(out: &mut [u8], nblocks: usize, state: &mut [u64; 25]) {
    keccak_squeezeblocks(out, nblocks, state, 136);
}
 /*************************************************
 * Name:        shake128
 *
 * Description: SHAKE128 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *out:      pointer to output
 *              - size_t outlen:     requested output length in bytes
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen:      length of input in bytes
 **************************************************/
     const SHAKE128_RATE: usize  = 168;
     const SHAKE256_RATE: usize  = 136;
     const SHA3_256_RATE:usize   = 136;
 pub fn shake128(out: &mut [u8], in_data: &[u8]) {
    let mut i = 0;
    let mut nblocks = out.len() / 168;
    let mut t = [0u8; 168];
    let mut state = crate::xof_state::KeccakState::new();

    shake128_absorb(&mut state, in_data);
    shake128_squeezeblocks(out, nblocks, &mut state);

    i += nblocks * SHAKE128_RATE;
    nblocks = out.len() - (nblocks * SHAKE128_RATE);

    if nblocks > 0 {
        shake128_squeezeblocks(&mut t, 1, &mut state);
        out[i..].copy_from_slice(&t[..nblocks]);
    }
}
 
 /*************************************************
 * Name:        shake256
 *
 * Description: SHAKE256 XOF with non-incremental API
 *
 * Arguments:   - uint8_t *out:      pointer to output
 *              - size_t outlen:     requested output length in bytes
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen:      length of input in bytes
 **************************************************/
 pub fn shake256(out: &mut [u8], outlen: usize, in_data: &[u8]) {
    // Ensure outlen does not exceed the length of out
    let outlen = std::cmp::min(outlen, out.len());

    let mut nblocks = outlen / SHAKE256_RATE;
    let mut t = [0u8; SHAKE256_RATE];
    let mut state = [0u64; 25];

    shake256_absorb(&mut state, &in_data);
    shake256_squeezeblocks(&mut out[..nblocks * SHAKE256_RATE], nblocks, &mut state);

    let remaining = outlen % SHAKE256_RATE;
    if remaining > 0 {
        shake256_squeezeblocks(&mut t, 1, &mut state);
        out[nblocks * SHAKE256_RATE..nblocks * SHAKE256_RATE + remaining].copy_from_slice(&t[..remaining]);
    }
}

 
 /*************************************************
 * Name:        sha3_256
 *
 * Description: SHA3-256 with non-incremental API
 *
 * Arguments:   - uint8_t *h:        pointer to output (32 bytes)
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen:      length of input in bytes
 **************************************************/
 pub fn sha3_256(h: &mut [u8; 32], in_data: &[u8]) {
     let mut s = [0u64; 25];
    let mut t = [0u8; SHA3_256_RATE];

    keccak_absorb(&mut s, SHA3_256_RATE, in_data, in_data.len(), 0x06);
    keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_256_RATE);

    h.copy_from_slice(&t[..32]);
}
 /*************************************************
 * Name:        sha3_512
 *
 * Description: SHA3-512 with non-incremental API
 *
 * Arguments:   - uint8_t *h:        pointer to output (64 bytes)
 *              - const uint8_t *in: pointer to input
 *              - size_t inlen:      length of input in bytes
 **************************************************/
 const SHA3_512_RATE: usize = 72;

 pub fn sha3_512(h: &mut [u8; 64], in_data: &[u8], size: usize) {
     let mut s = [0u64; 25];
     let mut t = [0u8; SHA3_512_RATE];
 
     keccak_absorb(&mut s, SHA3_512_RATE, in_data, size, 0x06);
     keccak_squeezeblocks(&mut t, 1, &mut s, SHA3_512_RATE);
 
     h.copy_from_slice(&t[..64]);
 }
 
}