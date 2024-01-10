pub mod indcpa
{

    
    /*************************************************
    * Name:        pack_pk
    *
    * Description: Serialize the public key as concatenation of the
    *              serialized vector of polynomials pk
    *              and the public seed used to generate the matrix A.
    *
    * Arguments:   uint8_t *r:          pointer to the output serialized public key
    *              polyvec *pk:         pointer to the input public-key polyvec
    *              const uint8_t *seed: pointer to the input public seed
    **************************************************/
    use crate::{poly, poly_struct, polyvec_struct, get_env_var};
    use crate::xof_state::XofAbsorb;

    pub fn pack_pk(r: &mut [u8], pk: &polyvec_struct::PolyVec, seed: &[u8]) {
        let kyber_symbytes: u32 = crate::get_env_var("KYBER_SYMBYTES").unwrap();
        let kyber_polyvecbytes: usize = crate::get_env_var("KYBER_polyvecbytes").unwrap();
            crate::polyvec::polyvec::polyvec_tobytes(r, pk);
            for i in 0..kyber_symbytes {
                r[i as usize + kyber_polyvecbytes] = seed[i as usize];
            }
        
    }

    /*************************************************
    * Name:        unpack_pk
    *
    * Description: De-serialize public key from a byte array;
    *              approximate inverse of pack_pk
    *
    * Arguments:   - polyvec *pk:             pointer to output public-key
    *                                         polynomial vector
    *              - uint8_t *seed:           pointer to output seed to generate
    *                                         matrix A
    *              - const uint8_t *packedpk: pointer to input serialized public key
    **************************************************/
    pub fn unpack_pk(pk: &mut polyvec_struct::PolyVec, seed: &mut [u8], packedpk: &[u8]) {
        let kyber_polyvecbytes: usize = crate::get_env_var("KYBER_POLYVECBYTES").unwrap();
        let kyber_symbytes: u32 = crate::get_env_var("KYBER_SYMBYTES").unwrap();
            crate::polyvec::polyvec::polyvec_frombytes(pk, packedpk);
            for i in 0..kyber_symbytes {
                seed[i as usize] = packedpk[i as usize + kyber_polyvecbytes];
            }
        }
    
    /*************************************************
    * Name:        pack_sk
    *
    * Description: Serialize the secret key
    *
    * Arguments:   - uint8_t *r:  pointer to output serialized secret key
    *              - polyvec *sk: pointer to input vector of polynomials (secret key)
    **************************************************/
    pub fn pack_sk(r: &mut [u8], sk: &polyvec_struct::PolyVec) {
        crate::polyvec::polyvec::polyvec_tobytes(r, sk);
    }
    /*************************************************
    * Name:        unpack_sk
    *
    * Description: De-serialize the secret key;
    *              inverse of pack_sk
    *
    * Arguments:   - polyvec *sk:             pointer to output vector of
    *                                         polynomials (secret key)
    *              - const uint8_t *packedsk: pointer to input serialized secret key
    **************************************************/
    pub fn unpack_sk(sk: &mut polyvec_struct::PolyVec, packedsk: &[u8]) {
        crate::polyvec::polyvec::polyvec_frombytes(sk, packedsk);
    }
    
    /*************************************************
    * Name:        pack_ciphertext
    *
    * Description: Serialize the ciphertext as concatenation of the
    *              compressed and serialized vector of polynomials b
    *              and the compressed and serialized polynomial v
    *
    * Arguments:   uint8_t *r: pointer to the output serialized ciphertext
    *              poly *pk:   pointer to the input vector of polynomials b
    *              poly *v:    pointer to the input polynomial v
    **************************************************/
    pub fn pack_ciphertext(r: &mut [u8], b: &mut polyvec_struct::PolyVec, v: &mut poly_struct::PolyStruct) {
        let kyber_polyveccompressedbytes: usize = crate::get_env_var("KYBER_POLYVECCOMPRESSEDBYTES").unwrap();
            crate::polyvec::polyvec::polyvec_compress(r, b);
            poly::poly::poly_compress(&mut r[kyber_polyveccompressedbytes..], v);
        }
    
    
    /*************************************************
    * Name:        unpack_ciphertext
    *
    * Description: De-serialize and decompress ciphertext from a byte array;
    *              approximate inverse of pack_ciphertext
    *
    * Arguments:   - polyvec *b:       pointer to the output vector of polynomials b
    *              - poly *v:          pointer to the output polynomial v
    *              - const uint8_t *c: pointer to the input serialized ciphertext
    **************************************************/
    pub fn unpack_ciphertext(b: &mut polyvec_struct::PolyVec, v: &mut poly_struct::PolyStruct, c: &[u8]) {
        let kyber_polyveccompressedbytes: usize = crate::get_env_var("KYBER_POLYVECCOMPRESSEDBYTES").unwrap();
        crate::polyvec::polyvec::polyvec_decompress(b, c);
        poly::poly::poly_decompress(v, &c[kyber_polyveccompressedbytes..]);
    }
        
    
    /*************************************************
    * Name:        rej_uniform
    *
    * Description: Run rejection sampling on uniform random bytes to generate
    *              uniform random integers mod q
    *
    * Arguments:   - int16_t *r:          pointer to output buffer
    *              - unsigned int len:    requested number of 16-bit integers
    *                                     (uniform mod q)
    *              - const uint8_t *buf:  pointer to input buffer
    *                                     (assumed to be uniform random bytes)
    *              - unsigned int buflen: length of input buffer in bytes
    *
    * Returns number of sampled 16-bit integers (at most len)
    **************************************************/
    pub fn rej_uniform(r: &mut [i16], len: usize, buf: &[u8], buflen: usize) -> usize {
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            let mut ctr = 0;
            let mut pos = 0;
            let mut val0: u16;
            let mut val1: u16;

            while ctr < len && pos + 3 <= buflen {
                val0 = ((buf[pos] as u16) | ((buf[pos + 1] as u16) << 8)) & 0xFFF;
                val1 = ((buf[pos + 1] as u16 >> 4) | ((buf[pos + 2] as u16) << 4)) & 0xFFF;
                pos += 3;

                if val0 < kyber_q as u16 {
                    r[ctr] = val0 as i16;
                    ctr += 1;
                }
                if ctr < len && val1 < kyber_q as u16 {
                    r[ctr] = val1 as i16;
                    ctr += 1;
                }
            }

            ctr
        } 

    
    /*************************************************
    * Name:        gen_matrix
    *
    * Description: Deterministically generate matrix A (or the transpose of A)
    *              from a seed. Entries of the matrix are polynomials that look
    *              uniformly random. Performs rejection sampling on output of
    *              a XOF
    *
    * Arguments:   - polyvec *a:          pointer to ouptput matrix A
    *              - const uint8_t *seed: pointer to input seed
    *              - int transposed:      boolean deciding whether A or A^T
    *                                     is generated
    **************************************************/
    pub fn gen_matrix(a: &mut Vec<polyvec_struct::PolyVec>, mut seed: &Vec<u8>, transposed: bool) {
        /*
        #define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q \
                             + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)

                             #define XOF_BLOCKBYTES SHAKE128_RATE
                             #define SHAKE128_RATE 168

         */ 
        const XOF_BLOCKBYTES: usize = 168;
        let kyber_n: usize = crate::get_env_var("KYBER_N").unwrap();
        let kyber_q: usize = crate::get_env_var("KYBER_Q").unwrap();
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
        let kyber_ssbytes: u32 = crate::get_env_var("KYBER_SSBYTES").unwrap();
            let gen_matrix_nblocks: usize = ((12 * kyber_n / 8 * (1 << 12) / kyber_q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES);
           
            let mut ctr;
            let mut buflen;
            let mut off;
            let mut buf = vec![0u8; gen_matrix_nblocks * XOF_BLOCKBYTES + 2];

            if kyber_ssbytes == 32
            {
                let mut state = crate::xof_state::KeccakState::new();
                for i in 0..kyber_k {
                    for j in 0..kyber_k {
                        if transposed
                        {
                            crate::symmetric_shake::symmetric_shake::kyber_shake128_absorb(&mut state, &seed, i as u8, j as u8);
                        }
                        else
                        {
                            let seed_slice: &[u8] = &seed;


                            crate::symmetric_shake::symmetric_shake::kyber_shake128_absorb(&mut state, seed_slice, j as u8,  i as u8);

                        }
                        crate::fips202::fips202::shake128_squeezeblocks(&mut buf, gen_matrix_nblocks, &mut state);

                        buflen = gen_matrix_nblocks * XOF_BLOCKBYTES;
                        ctr = rej_uniform(&mut a[i as usize].vec[j as usize].coeffs, kyber_n as usize, &buf, buflen);

                        while ctr < kyber_n as usize {
                            off = buflen % 3;
                            for k in 0..off {
                                buf[k] = buf[buflen - off + k];
                            }
                            crate::fips202::fips202::shake128_squeezeblocks(&mut buf[off..], 1, &mut state);
                            buflen = off + XOF_BLOCKBYTES;
                            ctr += rej_uniform(&mut a[i as usize].vec[j as usize].coeffs[ctr..], kyber_n as usize - ctr, &buf, buflen);
                        }
                    }
                }
            }
            else
            {
                let mut state = crate::xof_state::Aes256CtrCtx::new();
                for i in 0..kyber_k {
                    for j in 0..kyber_k {
                        if transposed
                        {
                            crate::symmetric_aes::symmetric_aes::kyber_aes256xof_absorb(&mut state, seed, i as u8, j as u8);
                        }
                        else
                        {
                            crate::symmetric_aes::symmetric_aes::kyber_aes256xof_absorb(&mut state, seed, j as u8, i as u8);
                        }


                        buflen = gen_matrix_nblocks * XOF_BLOCKBYTES;
                        ctr = rej_uniform(&mut a[i as usize].vec[j as usize].coeffs, kyber_n as usize, &buf, buflen);

                        while ctr < kyber_n as usize {
                            off = buflen % 3;
                            for k in 0..off {
                                buf[k] = buf[buflen - off + k];
                            }

                            buflen = off + XOF_BLOCKBYTES;
                            ctr += rej_uniform(&mut a[i as usize].vec[j as usize].coeffs[ctr..], kyber_n as usize - ctr, &buf, buflen);
                        }
                    }
                }
            }
        }

    

    /*************************************************
    * Name:        indcpa_keypair
    *
    * Description: Generates public and private key for the CPA-secure
    *              public-key encryption scheme underlying Kyber
    *
    * Arguments:   - uint8_t *pk: pointer to output public key
    *                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
    *              - uint8_t *sk: pointer to output private key
                                  (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
    **************************************************/


    pub fn indcpa_keypair(pk: &mut Vec<u8>, sk: &mut Vec<u8>) {
        let kyber_k: usize = crate::get_env_var("KYBER_K").unwrap();
        let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();
    
        // Create a vector to represent the buffer
        let mut buf = vec![0u8; 2 * kyber_symbytes];
    
        // Create mutable vectors for publicseed and noiseseed
        let mut publicseed = vec![0u8; kyber_symbytes];
        let mut noiseseed = vec![0u8; kyber_symbytes];
    
        // Copy data from buf to publicseed and noiseseed
        publicseed.copy_from_slice(&buf[0..kyber_symbytes]);
        noiseseed.copy_from_slice(&buf[kyber_symbytes..]);
    
        let mut nonce = 0;
        let mut a = vec![polyvec_struct::PolyVec::new(); kyber_k];
    
        let mut e = polyvec_struct::PolyVec::new();
        let mut pkpv = polyvec_struct::PolyVec::new();
        let mut skpv = polyvec_struct::PolyVec::new();
    
        unsafe {
            crate::library_loading::call_randombytes(publicseed.as_mut_ptr(), kyber_symbytes as u64);
        }

        for i in 0..publicseed.len()
        {
            buf[i] = publicseed[i];
        }
    let ninty:String = get_env_var("KYBER_90S").unwrap();

        if ninty == "true"
        { 
            use sha2::{Sha512, Digest};
            let mut hasher = Sha512::new();
            hasher.update(&buf);
            let result = hasher.finalize();
    
            if buf.len() >= 64 {
                buf[..64].copy_from_slice(&result[..64]);
            } else {
                panic!("Error with hash_g");
            }
        } else {
            let mut buf_array = [0u8; 64];
            buf_array.copy_from_slice(&buf);
    
            let mut buff_copy = buf_array.clone();
            crate::fips202::fips202::sha3_512(&mut buf_array, &buff_copy, kyber_symbytes);
            buf.copy_from_slice(&buf_array);

        }

        publicseed.copy_from_slice(&buf[0..kyber_symbytes]);
    
        gen_matrix(&mut a, &mut publicseed, false);
    
        for i in 0..kyber_k {
            poly::poly::poly_getnoise_eta1(&mut skpv.vec[i as usize], &noiseseed, nonce);
            nonce += 1;
        }
        for i in 0..kyber_k {
            poly::poly::poly_getnoise_eta1(&mut e.vec[i as usize], &noiseseed, nonce);
            nonce += 1;
        }
    
        crate::polyvec::polyvec::polyvec_ntt(&mut skpv);
        crate::polyvec::polyvec::polyvec_ntt(&mut e);
    
        // matrix-vector multiplication
        for i in 0..kyber_k {
            crate::polyvec::polyvec::polyvec_pointwise_acc_montgomery(&mut pkpv.vec[i as usize], &a[i as usize], &skpv);
            poly::poly::poly_tomont(&mut pkpv.vec[i as usize]);
        }
    
        let pkpv_temp = pkpv.clone();
        crate::polyvec::polyvec::polyvec_add(&mut pkpv, &pkpv_temp, &e);
        crate::polyvec::polyvec::polyvec_reduce(&mut pkpv);
    
        pack_sk(sk, &skpv);
        pack_pk(pk, &pkpv, &publicseed);
    }
    

    /*************************************************
    * Name:        indcpa_enc
    *
    * Description: Encryption function of the CPA-secure
    *              public-key encryption scheme underlying Kyber.
    *
    * Arguments:   - uint8_t *c:           pointer to output ciphertext
    *                                      (of length KYBER_INDCPA_BYTES bytes)
    *              - const uint8_t *m:     pointer to input message
    *                                      (of length KYBER_INDCPA_MSGBYTES bytes)
    *              - const uint8_t *pk:    pointer to input public key
    *                                      (of length KYBER_INDCPA_PUBLICKEYBYTES)
    *              - const uint8_t *coins: pointer to input random coins
    *                                      used as seed (of length kyber_symbytes)
    *                                      to deterministically generate all
    *                                      randomness
    **************************************************/
    pub fn indcpa_enc(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {

        let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();
        let kyber_k: usize = crate::get_env_var("KYBER_K").unwrap();
            let mut seed = vec![0u8; kyber_symbytes];
            let mut nonce = 0;
            let mut sp = polyvec_struct::PolyVec::new();
            let mut pkpv = polyvec_struct::PolyVec::new();
            let mut ep = polyvec_struct::PolyVec::new();
            let mut at = vec![polyvec_struct::PolyVec::new(); kyber_k];
            let mut bp = polyvec_struct::PolyVec::new();
            let mut v = poly_struct::PolyStruct::new();
            let mut k = poly_struct::PolyStruct::new();
            let mut epp = poly_struct::PolyStruct::new();

            unpack_pk(&mut pkpv, &mut seed, pk);
            poly::poly::poly_frommsg(&mut k, m);

            gen_matrix(&mut at, &seed, true);
            for i in 0..kyber_k {
                poly::poly::poly_getnoise_eta1(&mut sp.vec[i as usize], coins, nonce);
                nonce += 1;
            }
            for i in 0..kyber_k {
                poly::poly::poly_getnoise_eta2(&mut ep.vec[i as usize], coins, nonce);
                nonce += 1;
            }
            poly::poly::poly_getnoise_eta2(&mut epp, &coins, nonce);
            nonce += 1;

            crate::polyvec::polyvec::polyvec_ntt(&mut sp);

            // matrix-vector multiplication
            for i in 0..kyber_k {
                let mut temp_bp = polyvec_struct::PolyVec::new();
                crate::polyvec::polyvec::polyvec_pointwise_acc_montgomery(&mut temp_bp.vec[i as usize], &at[i as usize], &sp);
                crate::polyvec::polyvec::polyvec_add(&mut bp, &temp_bp, &ep);
            }

            let mut temp_v = poly_struct::PolyStruct::new();
            crate::polyvec::polyvec::polyvec_pointwise_acc_montgomery(&mut temp_v, &pkpv, &sp);
            let temp_bp_ii = bp.clone();
            crate::polyvec::polyvec::polyvec_add(&mut bp, & temp_bp_ii, &ep);
            v = temp_v;

            crate::polyvec::polyvec::polyvec_invntt_tomont(&mut bp);
            poly::poly::poly_invntt_tomont(&mut v);

            let mut temp_bp2 = polyvec_struct::PolyVec::new();
            crate::polyvec::polyvec::polyvec_add(&mut temp_bp2, &bp, &ep);
            bp = temp_bp2;

            let mut temp_v2 = poly_struct::PolyStruct::new();
            poly::poly::poly_add(&mut temp_v2, &v, &epp);
            v = temp_v2;

            let mut temp_v3 = poly_struct::PolyStruct::new();
            poly::poly::poly_add(&mut temp_v3, &v, &k);
            v = temp_v3;

            crate::polyvec::polyvec::polyvec_reduce(&mut bp);
            poly::poly::poly_reduce(&mut v);

            pack_ciphertext(c, &mut bp, &mut v);
        }
    
    /*************************************************
    * Name:        indcpa_dec
    *
    * Description: Decryption function of the CPA-secure
    *              public-key encryption scheme underlying Kyber.
    *
    * Arguments:   - uint8_t *m:        pointer to output decrypted message
    *                                   (of length KYBER_INDCPA_MSGBYTES)
    *              - const uint8_t *c:  pointer to input ciphertext
    *                                   (of length KYBER_INDCPA_BYTES)
    *              - const uint8_t *sk: pointer to input secret key
    *                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
    **************************************************/
    pub fn indcpa_dec(m: &mut [u8], c: &[u8], sk: &[u8]) {
        let mut bp = polyvec_struct::PolyVec::new();
        let mut skpv = polyvec_struct::PolyVec::new();
        let mut v = poly_struct::PolyStruct::new();
        let mut mp = poly_struct::PolyStruct::new();

        unpack_ciphertext(&mut bp, &mut v, c);
        unpack_sk(&mut skpv, sk);

        crate::polyvec::polyvec::polyvec_ntt(&mut bp);
        crate::polyvec::polyvec::polyvec_pointwise_acc_montgomery(&mut mp, &skpv, &bp);
        poly::poly::poly_invntt_tomont(&mut mp);

        let mut result = poly_struct::PolyStruct::new();  // Create a new variable to store the result
        poly::poly::poly_sub(&mut result, &v, &mp);  // Store the result of the subtraction in 'result'
        poly::poly::poly_reduce(&mut result);

        poly::poly::poly_tomsg(m, &mut result);  // Use 'result' instead of 'mp'
    }


}