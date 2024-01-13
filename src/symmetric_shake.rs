
pub mod symmetric_shake {
    /*************************************************
    * Name:        kyber_shake128_absorb
    *
    * Description: Absorb step of the SHAKE128 specialized for the Kyber context.
    *
    * Arguments:   - keccak_state *state: pointer to (uninitialized) output
    *                                     Keccak state
    *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input
    *                                     to be absorbed into state
    *              - uint8_t i            additional byte of input
    *              - uint8_t j            additional byte of input
    **************************************************/
    pub fn kyber_shake128_absorb(state: &mut crate::xof_state::KeccakState, seed:&[u8], x: u8, y: u8) {
        let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();
            let mut extseed = vec![0u8; kyber_symbytes as usize + 2];

            for i in 0..kyber_symbytes{
                extseed[i as usize] = seed[i as usize];
            }

            extseed[kyber_symbytes] = x;
            extseed[kyber_symbytes + 1usize] = y;
            let seed_slice: &[u8] = &extseed;
            crate::fips202::fips202::shake128_absorb(state, &seed_slice);
        
    }


    /*************************************************
* Name:        kyber_shake256_prf
*
* Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
*              and then generates outlen bytes of SHAKE256 output
*
* Arguments:   - uint8_t *out:       pointer to output
*              - size_t outlen:      number of requested output bytes
*              - const uint8_t *key: pointer to the key
*                                    (of length kyber_symbytes)
*              - uint8_t nonce:      single-byte nonce (public PRF input)
**************************************************/

    pub fn kyber_shake256_prf(out: &mut [u8], key: &[u8], nonce: u8) {
        let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();

            let mut extkey = vec![0u8; kyber_symbytes as usize+ 1];

            for i in  0..kyber_symbytes
            {
                extkey[i as usize] = key[i as usize];        
            }
            let len = extkey.len() - 1;
                extkey[len] = nonce;

                crate::fips202::fips202::shake256(out, out.len(), &extkey);
    
        
    }
}