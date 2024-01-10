pub mod poly
{
        /*************************************************
    * Name:        poly_compress
    *
    * Description: Compression and subsequent serialization of a polynomial
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (of length KYBER_POLYCOMPRESSEDBYTES)
    *              - poly *a:    pointer to input polynomial
    **************************************************/
    pub fn poly_compress(r: &mut [u8], a: &mut crate::poly_struct::PolyStruct) {
       
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
        let kyber_polycompressedbytes: u32 = crate::get_env_var("KYBER_POLYCOMPRESSEDBYTES").unwrap();
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            let mut t: [u8; 8] = [0; 8];
            let mut r_index = 0; // Mutable index variable

            poly_csubq(a);

            if kyber_polycompressedbytes == 128 {
                for i in 0..kyber_n / 8 {
                    for j in 0..8 {
                        t[j] = (((((a.coeffs[(8 * i + j as u32) as usize] as u32) << 4) + (kyber_q / 2) as u32) / kyber_q as u32) & 15) as u8;
                    }

                    r[r_index] = t[0] | (t[1] << 4);
                    r[r_index + 1] = t[2] | (t[3] << 4);
                    r[r_index + 2] = t[4] | (t[5] << 4);
                    r[r_index + 3] = t[6] | (t[7] << 4);
                    r_index += 4; // Update the index
                }
            } else if kyber_polycompressedbytes == 160 {
                for i in 0..kyber_n / 8 {
                    for j in 0..8 {
                        t[j] = (((((a.coeffs[(8 * i + j as u32) as usize] as u32) << 5) + (kyber_q / 2) as u32) / kyber_q as u32) & 31) as u8;
                    }

                    r[r_index] = (t[0] >> 0) | (t[1] << 5);
                    r[r_index + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                    r[r_index + 2] = (t[3] >> 1) | (t[4] << 4);
                    r[r_index + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                    r[r_index + 4] = (t[6] >> 2) | (t[7] << 3);
                    r_index += 5; // Update the index
                }
        }
    }


    /*************************************************
* Name:        poly_decompress
*
* Description: De-serialization and subsequent decompression of a polynomial;
*              approximate inverse of poly_compress
*
* Arguments:   - poly *r:          pointer to output polynomial
*              - const uint8_t *a: pointer to input byte array
*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
**************************************************/
    pub fn poly_decompress(r: &mut crate::poly_struct::PolyStruct, mut a: &[u8]) {
        let kyber_polycompressedbytes: u32 = crate::get_env_var("KYBER_POLYCOMPRESSEDBYTES").unwrap();
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            if kyber_polycompressedbytes == 128 {
                for i in 0..kyber_n / 2 {
                    r.coeffs[(2 * i + 0) as usize] = ((((a[0] & 15) * kyber_q as u8) + 8) >> 4) as i16;
                    r.coeffs[(2 * i + 1) as usize] = ((((a[0] >> 4)  * kyber_q as u8) + 8) >> 4) as i16;
                    a = &a[1..];
                }
            } else if kyber_polycompressedbytes == 160 {
                for i in 0..kyber_n / 8 {
                    let mut t: [u8; 8] = [0; 8];

                    t[0] = a[0] >> 0;
                    t[1] = (a[0] >> 5) | (a[1] << 3);
                    t[2] = a[1] >> 2;
                    t[3] = (a[1] >> 7) | (a[2] << 1);
                    t[4] = (a[2] >> 4) | (a[3] << 4);
                    t[5] = a[3] >> 1;
                    t[6] = (a[3] >> 6) | (a[4] << 2);
                    t[7] = a[4] >> 3;
                    a = &a[5..];

                    for j in 0..8 {
                        r.coeffs[(8 * i + j) as usize] = ((((t[j as usize] & 31) as u32 * kyber_q) + 16) >> 5) as i16;
                    }
                }
            }
        
    }


    /*************************************************
* Name:        poly_tobytes
*
* Description: Serialization of a polynomial
*
* Arguments:   - uint8_t *r: pointer to output byte array
*                            (needs space for kyber_polybytes bytes)
*              - poly *a:    pointer to input polynomial
**************************************************/
    pub fn poly_tobytes(r: &mut [u8], a: &mut crate::poly_struct::PolyStruct){

        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
                let mut t0: u16;
                let mut t1: u16;

                poly_csubq(a);

                for i in 0..kyber_n / 2 {
                    t0 = a.coeffs[(2 * i) as usize] as u16;
                    t1 = a.coeffs[(2 * i + 1) as usize] as u16;
                    r[(3 * i + 0) as usize] = (t0 >> 0) as u8;
                    r[(3 * i + 1) as usize] = ((t0 >> 8) | (t1 << 4)) as u8;
                    r[(3 * i + 2) as usize] = (t1 >> 4) as u8;
                }
            
        }
    
        /*************************************************
    * Name:        poly_frombytes
    *
    * Description: De-serialization of a polynomial;
    *              inverse of poly_tobytes
    *
    * Arguments:   - poly *r:          pointer to output polynomial
    *              - const uint8_t *a: pointer to input byte array
    *                                  (of kyber_polybytes bytes)
    **************************************************/
    pub fn poly_frombytes(r: &mut crate::poly_struct::PolyStruct, a: &[u8]) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n / 2 {
                r.coeffs[(2 * i) as usize] = (((a[(3 * i + 0) as usize] as u16) | ((a[(3 * i + 1) as usize] as u16) << 8)) & 0xFFF) as i16;
                r.coeffs[(2 * i + 1) as usize] = (((a[(3 * i + 1) as usize] as u16) >> 4 | ((a[(3 * i + 2) as usize] as u16) << 4)) & 0xFFF) as i16;
            }
        }
        
    


    /*************************************************
* Name:        poly_frommsg
*
* Description: Convert 32-byte message to polynomial
*
* Arguments:   - poly *r:            pointer to output polynomial
*              - const uint8_t *msg: pointer to input message
**************************************************/
        pub fn poly_frommsg(r: &mut crate::poly_struct::PolyStruct, msg: &[u8]) {
            let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
                let mut mask: i16;

                /* TODO sort this out \/
                #[cfg(not(Kkyber_indcpa_msgbytes == params.kyber_n / 8))]
                compile_error!("Kyber_indcpa_msgbytes must be equal to kyber_n/8 bytes!");
                */
                for i in 0..kyber_n / 8 {
                    for j in 0..8 {
                        mask = -(((msg[i as usize] >> j) & 1) as i16);
                        r.coeffs[(8 * i + j) as usize] = mask & ((kyber_q as i16 + 1) / 2);
                    }
                }
            
        }
    
        /*************************************************
    * Name:        poly_tomsg
    *
    * Description: Convert polynomial to 32-byte message
    *
    * Arguments:   - uint8_t *msg: pointer to output message
    *              - poly *a:      pointer to input polynomial
    **************************************************/
        pub fn poly_tomsg(msg: &mut [u8], a: &mut crate::poly_struct::PolyStruct) {
            let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            let kyber_q: u16 = crate::get_env_var("KYBER_Q").unwrap();
                let mut t: u16;

                poly_csubq(a);

                for i in 0..kyber_n / 8 {
                    msg[i as usize] = 0;
                    for j in 0..8 {
                        t = ((((a.coeffs[(8 * i + j) as usize] as u16) << 1) + kyber_q/ 2) / kyber_q) & 1;
                        msg[i as usize] |= (t << j) as u8;
                    }
                
            }
        }
    
        /*************************************************
    * Name:        poly_getnoise_eta1
    *
    * Description: Sample a polynomial deterministically from a seed and a nonce,
    *              with output polynomial close to centered binomial distribution
    *              with parameter KYBER_ETA1
    *
    * Arguments:   - poly *r:             pointer to output polynomial
    *              - const uint8_t *seed: pointer to input seed
    *                                     (of length kyber_symbytes bytes)
    *              - uint8_t nonce:       one-byte input nonce
    **************************************************/
        pub fn poly_getnoise_eta1(r: &mut crate::poly_struct::PolyStruct, seed: &[u8], nonce: u8) {
            let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            let kyber_eta1: u32 = crate::get_env_var("KYBER_ETA1").unwrap();
            let kyber_ssbytes: u32 = crate::get_env_var("KYBER_SSBYTES").unwrap();

                let mut buf = vec![0u8; kyber_eta1 as usize * kyber_n as usize / 4];
                if kyber_ssbytes != 32
                {
                    crate::symmetric_aes::symmetric_aes::kyber_aes256ctr_prf(&mut buf, seed, nonce);
                }
                else
                {
                    crate::symmetric_shake::symmetric_shake::kyber_shake256_prf(&mut buf, seed, nonce);
                }


                crate::cbd::cbd::cbd_eta1(r, &buf);
            
        }
    
        /*************************************************
    * Name:        poly_getnoise_eta2
    *
    * Description: Sample a polynomial deterministically from a seed and a nonce,
    *              with output polynomial close to centered binomial distribution
    *              with parameter kyber_eta2
    *
    * Arguments:   - poly *r:             pointer to output polynomial
    *              - const uint8_t *seed: pointer to input seed
    *                                     (of length kyber_symbytes bytes)
    *              - uint8_t nonce:       one-byte input nonce
    **************************************************/
        pub fn poly_getnoise_eta2(r: &mut crate::poly_struct::PolyStruct, seed: &[u8], nonce: u8) {
            let kyber_eta2: u32 = crate::get_env_var("KYBER_ETA2").unwrap();
            let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            let kyber_ssbytes: u32 = crate::get_env_var("KYBER_SSBYTES").unwrap();

                let mut buf = vec![0u8; kyber_eta2 as usize * kyber_n as usize / 4];
                if kyber_ssbytes != 32
                {
                    crate::symmetric_aes::symmetric_aes::kyber_aes256ctr_prf(&mut buf, seed, nonce);
                }
                else
                {
                    crate::symmetric_shake::symmetric_shake::kyber_shake256_prf(&mut buf, seed, nonce);
                }
                crate::cbd::cbd::cbd_eta2(r, &buf);
            
        }
    
    
        /*************************************************
    * Name:        poly_ntt
    *
    * Description: Computes negacyclic number-theoretic transform (NTT) of
    *              a polynomial in place;
    *              inputs assumed to be in normal order, output in bitreversed order
    *
    * Arguments:   - uint16_t *r: pointer to in/output polynomial
    **************************************************/
        pub fn poly_ntt(r: &mut crate::poly_struct::PolyStruct) {
            crate::ntt::ntt::ntt(&mut r.coeffs);
            poly_reduce(r);
        }
        /*************************************************
    * Name:        poly_invntt_tomont
    *
    * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
    *              of a polynomial in place;
    *              inputs assumed to be in bitreversed order, output in normal order
    *
    * Arguments:   - uint16_t *a: pointer to in/output polynomial
    **************************************************/
        pub fn poly_invntt_tomont(r: &mut crate::poly_struct::PolyStruct) {
            crate::ntt::ntt::invntt(&mut r.coeffs);
        }
    
        /*************************************************
    * Name:        poly_basemul_montgomery
    *
    * Description: Multiplication of two polynomials in NTT domain
    *
    * Arguments:   - poly *r:       pointer to output polynomial
    *              - const poly *a: pointer to first input polynomial
    *              - const poly *b: pointer to second input polynomial
    **************************************************/
    /*
    pub fn poly_basemul_montgomery(r: &mut crate::poly_struct::PolyStruct, a: &crate::poly_struct::PolyStruct, b: &crate::poly_struct::PolyStruct) {
        let kyber_params = crate::KYBER_PARAMS.lock().unwrap();
        if let Some(params) = &*kyber_params {
            for i in 0..params.kyber_n / 4 {
                // Adjust the slices to be 2 elements each
                crate::ntt::ntt::basemul(&mut r.coeffs[4 * i..4 * i + 2], &a.coeffs[4 * i..4 * i + 2], &b.coeffs[4 * i..4 * i + 2], crate::ntt::ntt::ZETAS[64 + i]);
                crate::ntt::ntt::basemul(&mut r.coeffs[4 * i + 2..4 * i + 4], &a.coeffs[4 * i + 2..4 * i + 4], &b.coeffs[4 * i + 2..4 * i + 4], -crate::ntt::ntt::ZETAS[64 + i]);
            }
        }
    }
    */
    pub fn poly_basemul_montgomery(r: &mut crate::poly_struct::PolyStruct, a: &crate::poly_struct::PolyStruct, b: &crate::poly_struct::PolyStruct) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();

            for i in 0..kyber_n / 4 {
                // Temporary arrays to hold pairs of coefficients
                let mut temp_r1 = [r.coeffs[(4 * i) as usize], r.coeffs[(4 * i + 1) as usize]];
                let mut temp_a1 = [a.coeffs[(4 * i) as usize], a.coeffs[(4 * i + 1) as usize]];
                let temp_b1 = [b.coeffs[(4 * i) as usize], b.coeffs[(4 * i + 1) as usize]];

                let mut temp_r2 = [r.coeffs[(4 * i + 2) as usize], r.coeffs[(4 * i + 3) as usize]];
                let mut temp_a2 = [a.coeffs[(4 * i + 2) as usize], a.coeffs[(4 * i + 3) as usize]];
                let temp_b2 = [b.coeffs[(4 * i + 2) as usize], b.coeffs[(4 * i + 3) as usize]];

                // Perform basemul on these temporary arrays
                crate::ntt::ntt::basemul(&mut temp_r1, &mut temp_a1, &temp_b1, crate::ntt::ntt::ZETAS[(64 + i) as usize]);
                crate::ntt::ntt::basemul(&mut temp_r2, &mut temp_a2, &temp_b2, -crate::ntt::ntt::ZETAS[(64 + i) as usize]);

                // Assign the results back to the coeffs array
                r.coeffs[(4 * i) as usize] = temp_r1[0];
                r.coeffs[(4 * i + 1) as usize] = temp_r1[1];
                r.coeffs[(4 * i + 2) as usize] = temp_r2[0];
                r.coeffs[(4 * i + 3) as usize] = temp_r2[1];
            }
        
    }



    /*************************************************
    * Name:        poly_tomont
    *
    * Description: Inplace conversion of all coefficients of a polynomial
    *              from normal domain to Montgomery domain
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
   pub fn poly_tomont(r: &mut crate::poly_struct::PolyStruct) {
    let kyber_q: u64 = crate::get_env_var("KYBER_Q").unwrap();
    let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
           let f = (1u64 << 32) % kyber_q ;  // Assuming KYBER_Q is defined
           for i in 0..kyber_n {
               r.coeffs[i as usize] = crate::reduce::reduce::montgomery_reduce(r.coeffs[i as usize] as i32 * f as i32);
           }
       }
    

    /*************************************************
    * Name:        poly_reduce
    *
    * Description: Applies Barrett reduction to all coefficients of a polynomial
    *              for details of the Barrett reduction see comments in reduce.c
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    pub fn poly_reduce(r: &mut crate::poly_struct::PolyStruct) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n {
                r.coeffs[i as usize] = crate::reduce::reduce::barrett_reduce(r.coeffs[i as usize]);
            }
        
    }
    
    /*************************************************
    * Name:        poly_csubq
    *
    * Description: Applies conditional subtraction of q to each coefficient
    *              of a polynomial. For details of conditional subtraction
    *              of q see comments in reduce.c
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    
    pub fn poly_csubq(r: &mut crate::poly_struct::PolyStruct) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n {
                r.coeffs[i as usize] = crate::reduce::reduce::csubq(r.coeffs[i as usize]);
            }
        
    }
    /*************************************************
    * Name:        poly_add
    *
    * Description: Add two polynomials
    *
    * Arguments: - poly *r:       pointer to output polynomial
    *            - const poly *a: pointer to first input polynomial
    *            - const poly *b: pointer to second input polynomial
    **************************************************/
    pub fn poly_add(r: &mut crate::poly_struct::PolyStruct, a: &crate::poly_struct::PolyStruct, b: &crate::poly_struct::PolyStruct) 
     {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n {
                r.coeffs[i as usize] = a.coeffs[i as usize] + b.coeffs[i as usize];
            }
        
    }
    /*************************************************
    * Name:        poly_sub
    *
    * Description: Subtract two polynomials
    *
    * Arguments: - poly *r:       pointer to output polynomial
    *            - const poly *a: pointer to first input polynomial
    *            - const poly *b: pointer to second input polynomial
    **************************************************/
    pub fn poly_sub(r: &mut crate::poly_struct::PolyStruct, a: &crate::poly_struct::PolyStruct, b: &crate::poly_struct::PolyStruct) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n {
                r.coeffs[i as usize] = a.coeffs[i as usize] - b.coeffs[i as usize];
            }
        
    }

}