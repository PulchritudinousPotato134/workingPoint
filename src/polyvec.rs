
pub mod polyvec
{

    /*************************************************
    * Name:        polyvec_compress
    *
    * Description: Compress and serialize vector of polynomials
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (needs space for kyber_polyveccompressedbytes)
    *              - polyvec *a: pointer to input vector of polynomials
    **************************************************/
    pub fn polyvec_compress(r: &mut [u8], a: &mut crate::polyvec_struct::PolyVec) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
        let kyber_polyveccompressedbytes: u32 = crate::get_env_var("KYBER_POLYVECCOMPRESSEDBYTES").unwrap();
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            let mut r_idx = 0;

            polyvec_csubq(a);

            if kyber_polyveccompressedbytes == (kyber_k * 352) {
                let mut t = [0u16; 8];

                for i in 0..kyber_k {
                    for j in 0..(kyber_n / 8) {
                        for k in 0..8 {
                            t[k] = (((((a.vec[i as usize].coeffs[(8 * j + k as u32) as usize] as u32) << 11) + (kyber_q  / 2)) / (kyber_q)) & 0x7ff)  as u16;
                        }

                        r[r_idx + 0] = (t[0] >> 0) as u8;
                        r[r_idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                        r[r_idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                        r[r_idx + 3] = (t[2] >> 2) as u8;
                        r[r_idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                        r[r_idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                        r[r_idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                        r[r_idx + 7] = (t[5] >> 1) as u8;
                        r[r_idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                        r[r_idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                        r[r_idx + 10] = (t[7] >> 3) as u8;
                        r_idx += 11;
                    }
                }
            } else if kyber_polyveccompressedbytes == (kyber_k * 320) {
                let mut t = [0u16; 4];

                for i in 0..kyber_k {
                    for j in 0..(kyber_n / 4) {
                        for k in 0..4 {
                            t[k] = (((((a.vec[i as usize].coeffs[4 * j as usize + k as usize] as u32) << 10) + (kyber_q  / 2)) / (kyber_q )) & 0x3ff) as u16;
                        }

                        r[r_idx + 0] = (t[0] >> 0) as u8;
                        r[r_idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                        r[r_idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                        r[r_idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                        r[r_idx + 4] = (t[3] >> 2) as u8;
                        r_idx += 5;
                    }
                }
            } else {
                // Handle unsupported kyber_polyveccompressedbytes values
                panic!("kyber_polyveccompressedbytes needs to be in 320 * KYBER_K, 352 * KYBER_K");
            }
        
    }


    /*************************************************
    * Name:        polyvec_decompress
    *
    * Description: De-serialize and decompress vector of polynomials;
    *              approximate inverse of polyvec_compress
    *
    * Arguments:   - polyvec *r:       pointer to output vector of polynomials
    *              - const uint8_t *a: pointer to input byte array
    *                                  (of length kyber_polyveccompressedbytes)
    **************************************************/
    pub fn polyvec_decompress(r: &mut crate::polyvec_struct::PolyVec, a: &[u8]) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
        let kyber_polyveccompressedbytes: u32 = crate::get_env_var("KYBER_POLYVECCOMPRESSEDBYTES").unwrap();
            let mut idx = 0; // Initialize an index variable

            if kyber_polyveccompressedbytes == (kyber_k * 352) {
                let mut t = [0u16; 8];

                for i in 0..kyber_k {
                    for j in 0..(kyber_n / 8) {
                        t[0] = (a[idx] as u16 >> 0) | ((a[idx + 1] as u16) << 8);
                        t[1] = (a[idx + 1] as u16 >> 3) | ((a[idx + 2] as u16) << 5);
                        t[2] = (a[idx + 2] as u16 >> 6) | ((a[idx + 3] as u16) << 2) | ((a[idx + 4] as u16) << 10);
                        t[3] = (a[idx + 4] as u16 >> 1) | ((a[idx + 5] as u16) << 7);
                        t[4] = (a[idx + 5] as u16 >> 4) | ((a[idx + 6] as u16) << 4);
                        t[5] = (a[idx + 6] as u16 >> 7) | ((a[idx + 7] as u16) << 1) | ((a[idx + 8] as u16) << 9);
                        t[6] = (a[idx + 8] as u16 >> 2) | ((a[idx + 9] as u16) << 6);
                        t[7] = (a[idx + 9] as u16 >> 5) | ((a[idx + 10] as u16) << 3);
                        idx += 11; // Update the index

                        for k in 0..8 {
                            r.vec[i as usize].coeffs[8usize * j as usize + k] = (((t[k as usize] & 0x7FF) as u32 * kyber_q + 1024) >> 11) as i16;
                        }
                    }
                }
            } else if kyber_polyveccompressedbytes == (kyber_k * 320) {
                let mut t = [0u16; 4];

                for i in 0..kyber_k {
                    for j in 0..(kyber_n / 4) {
                        t[0] = (a[idx] as u16 >> 0) | ((a[idx + 1] as u16) << 8);
                        t[1] = (a[idx + 1] as u16 >> 2) | ((a[idx + 2] as u16) << 6);
                        t[2] = (a[idx + 2] as u16 >> 4) | ((a[idx + 3] as u16) << 4);
                        t[3] = (a[idx + 3] as u16 >> 6) | ((a[idx + 4] as u16) << 2);
                        idx += 5; // Update the index

                        for k in 0..4 {
                            r.vec[i as usize].coeffs[4usize * j as usize + k] = (((t[k as usize] & 0x3FF) as u32 * kyber_q + 512) >> 10) as i16;
                        }
                    }
                }
            } else {
                // Handle unsupported kyber_polyveccompressedbytes values
                panic!("kyber_polyveccompressedbytes needs to be in 320 * KYBER_K, 352 * KYBER_K");
            }
        
    }




    /*************************************************
    * Name:        polyvec_tobytes
    *
    * Description: Serialize vector of polynomials
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (needs space for KYBER_POLYVECBYTES)
    *              - polyvec *a: pointer to input vector of polynomials
    **************************************************/
    pub fn polyvec_tobytes(r: &mut [u8], a: &mut crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
        let kyber_polybytes: u32 = crate::get_env_var("KYBER_POLYBYTES").unwrap();
        let range:u32 = kyber_polybytes;
            let mut i = 0;
            for i in 0..kyber_k {
                crate::poly::poly::poly_tobytes(&mut r[(i * range) as usize..], &mut a.vec[i as usize]);
            }
        
    }
    /*************************************************
    * Name:        polyvec_frombytes
    *
    * Description: De-serialize vector of polynomials;
    *              inverse of polyvec_tobytes
    *
    * Arguments:   - uint8_t *r:       pointer to output byte array
    *              - const polyvec *a: pointer to input vector of polynomials
    *                                  (of length KYBER_POLYVECBYTES)
    **************************************************/
    pub fn polyvec_frombytes(r: &mut crate::polyvec_struct::PolyVec, a: &[u8]) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
        let kyber_polybytes: u32 = crate::get_env_var("KYBER_POLYBYTES").unwrap();
            for j in 0..kyber_k as usize {
                let start = j * kyber_polybytes as usize;
                let end = start + kyber_polybytes as usize;
                crate::poly::poly::poly_frombytes(&mut r.vec[j], &a[start..end]);
            }
        
    }


    /*************************************************
    * Name:        polyvec_ntt
    *
    * Description: Apply forward NTT to all elements of a vector of polynomials
    *
    * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
    **************************************************/
    pub fn polyvec_ntt(r: &mut crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            for i in 0..kyber_k {
                let mut x: crate::poly_struct::PolyStruct =  r.vec[i as usize].clone();
                crate::poly::poly::poly_ntt(&mut x);//&mut r.vec[i as usize]);
                r.vec[i as usize] = x;

            }
        
    }

    /*************************************************
    * Name:        polyvec_invntt_tomont
    *
    * Description: Apply inverse NTT to all elements of a vector of polynomials
    *              and multiply by Montgomery factor 2^16
    *
    * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
    **************************************************/
    pub fn polyvec_invntt_tomont(r: &mut crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            for i in 0..kyber_k {
                crate::poly::poly::poly_invntt_tomont(&mut r.vec[i as usize]);
            }
        
    }

    /*************************************************
    * Name:        polyvec_pointwise_acc_montgomery
    *
    * Description: Pointwise multiply elements of a and b, accumulate into r,
    *              and multiply by 2^-16.
    *
    * Arguments: - poly *r:          pointer to output polynomial
    *            - const polyvec *a: pointer to first input vector of polynomials
    *            - const polyvec *b: pointer to second input vector of polynomials
    **************************************************/
    pub fn polyvec_pointwise_acc_montgomery(r: &mut crate::poly_struct::PolyStruct, a: &crate::polyvec_struct::PolyVec, b: &crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            let mut result = crate::poly_struct::PolyStruct::new(); // Create a mutable result variable

            crate::poly::poly::poly_basemul_montgomery(r, &a.vec[0], &b.vec[0]);

            for i in 1..kyber_k {
                let mut t = crate::poly_struct::PolyStruct::new();
                crate::poly::poly::poly_basemul_montgomery(&mut t, &a.vec[i as usize], &b.vec[i as usize]);
                crate::poly::poly::poly_add(&mut result, r, &t); // Accumulate the result in `result`
            }

            *r = result; // Assign the accumulated result to `*r`
            crate::poly::poly::poly_reduce(r);
        
    }

    /*************************************************
    * Name:        polyvec_reduce
    *
    * Description: Applies Barrett reduction to each coefficient
    *              of each element of a vector of polynomials
    *              for details of the Barrett reduction see comments in reduce.c
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    pub fn polyvec_reduce(r: &mut crate::polyvec_struct::PolyVec) 
    {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            for i in 0..kyber_k {
                crate::poly::poly::poly_reduce(&mut r.vec[i as usize]);
            }
        
    }

    /*************************************************
    * Name:        polyvec_csubq
    *
    * Description: Applies conditional subtraction of q to each coefficient
    *              of each element of a vector of polynomials
    *              for details of conditional subtraction of q see comments in
    *              reduce.c
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    pub fn polyvec_csubq(r: &mut crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            for i in 0..kyber_k {
                crate::poly::poly::poly_csubq(&mut r.vec[i as usize]);
            
        }
    }
    /*************************************************
    * Name:        polyvec_add
    *
    * Description: Add vectors of polynomials
    *
    * Arguments: - polyvec *r:       pointer to output vector of polynomials
    *            - const polyvec *a: pointer to first input vector of polynomials
    *            - const polyvec *b: pointer to second input vector of polynomials
    **************************************************/
    pub fn polyvec_add(r: &mut crate::polyvec_struct::PolyVec, a: &crate::polyvec_struct::PolyVec, b: &crate::polyvec_struct::PolyVec) {
        let kyber_k: u32 = crate::get_env_var("KYBER_K").unwrap();
            for i in 0..kyber_k {
                crate::poly::poly::poly_add(&mut r.vec[i as usize], &a.vec[i as usize], &b.vec[i as usize]);
            }
        }
    }

