pub mod symmetric_aes
{
    pub fn kyber_aes256xof_absorb(state: &mut crate::xof_state::Aes256CtrCtx, seed: &[u8], x: u8, y: u8) {
        let kyber_symbytes: u32 = crate::get_env_var("KYBER_SYMBYTES").unwrap();
            assert_eq!(kyber_symbytes, 32, "Kyber-90s only supports kyber_symbytes = 32!");

            let mut expnonce = [0u8; 12];
            expnonce[0] = x;
            expnonce[1] = y;

            crate::aes256ctr::aes256ctr::aes256ctr_init(state, &seed, &expnonce);
        
    }

    pub fn kyber_aes256ctr_prf(out: &mut [u8], key: &[u8], nonce: u8) {

        let mut expnonce = [0u8; 12];
        expnonce[0] = nonce;
        let mut key_copy = [0u8; 32];
        key_copy.copy_from_slice(key);

        crate::aes256ctr::aes256ctr::aes256ctr_prf(out, out.len(), &key_copy, &expnonce);
    }
}
