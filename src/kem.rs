

trait HashFunction {
    fn hash_h(&self, out:  &mut [u8; 32], input: &[u8]);
    fn hash_g(&self, out: &mut [u8; 64], input: &[u8]);
    fn kdf(&self, out: &mut [u8; 32], input: &[u8]);
}


//#[cfg(feature = "kyber_90s")]
mod kyber_90s {
    use super::HashFunction;
    use sha2::{Sha256, Sha512, Digest};

    pub struct HashFunction90s;

    impl HashFunction for HashFunction90s {
        fn hash_h(&self, out:  &mut [u8; 32], input: &[u8]) {
            let mut hasher = Sha256::new();
            hasher.update(input);
            let result = hasher.finalize();
            if out.len() >= 32 {
                out[..32].copy_from_slice(&result[..32]);
            }
            else {
                panic!("Error with hash_h");
            }
        }
    
        fn hash_g(&self, out: &mut [u8; 64], input: &[u8]) {
            let mut hasher = Sha512::new();
            hasher.update(input);
            let result = hasher.finalize();
            if out.len() >= 64 {
                out[..64].copy_from_slice(&result[..64]);
            }
            else {
                panic!("Error with hash_g");
            }
        }
    
        fn kdf(&self, out: &mut [u8; 32], input: &[u8]) {
            let mut hasher = Sha256::new();
            hasher.update(input);
            let result = hasher.finalize();
            out.copy_from_slice(&result[..32]);
        }
    }
}

#[cfg(not(feature = "kyber_90s"))]
mod kyber_2020s {
    use super::HashFunction;
    use crate::fips202::fips202::sha3_256;
    use crate::fips202::fips202::sha3_512;
    use crate::fips202::fips202::shake256;



    pub struct HashFunctions;

    impl HashFunction for HashFunctions {
        fn hash_h(&self, out:  &mut [u8; 32], input: &[u8]) {
            sha3_256(out, input);
        }
        fn hash_g(&self, out:&mut [u8; 64], input: &[u8]) {
            sha3_512(out, input, input.len());
        }
        fn kdf(&self,out: &mut [u8; 32], input: &[u8])
        {
            shake256(out, 32, input);
        }
    }
}

pub mod kem{
    use std::env;
    use crate::config::KYBER_CIPHERTEXTBYTES;
    use crate::kem::{HashFunction, kyber_2020s, kyber_90s};
    use crate::{kyber, get_env_var};
    use crate::kyber_rng::KyberRng;


    fn selected_hash_function() -> Box<dyn HashFunction> {
        match env::var("KYBER_90S") {
            Ok(value) => {
                if value.eq_ignore_ascii_case("true")
                {
                    Box::new(kyber_90s::HashFunction90s)
                }
                else {
                    Box::new(kyber_2020s::HashFunctions)
                }

            }
            Err(_) => {
                Box::new(kyber_2020s::HashFunctions)
            }
        }

    }


   
    pub fn crypto_kem_keypair(mut pk: &mut Vec<u8>, mut sk: &mut Vec<u8>) -> Result<(), ()> {
        
        let kyber_i_secret: usize = crate::get_env_var("KYBER_INDCPA_SECRETKEYBYTES").unwrap();
        let kyber_i_public: usize = crate::get_env_var("KYBER_INDCPA_PUBLICKEYBYTES").unwrap();
        let kyber_secret: usize = crate::get_env_var("KYBER_SECRETKEYBYTES").unwrap();
        let kyber_public: usize = crate::get_env_var("KYBER_PUBLICKEYBYTES").unwrap();
        let kyber_sym: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();

            crate::indcpa::indcpa::indcpa_keypair(pk, sk);

            // Copy data from pk to sk
            for i in 0..kyber_i_public {
                sk[kyber_i_secret + i] = pk[i];
            }

            // Calculate hash_h(sk + kyber_secretkeybytes - 2 * kyber_symbytes, pk, kyber_publickeybytes)
            if sk.len() >= kyber_secret - 2 * kyber_sym + 32 {
                let hash_output_slice = &mut sk[kyber_secret - 2 * kyber_sym..kyber_secret - 2 * kyber_sym + 32];
                let hash_output_array: &mut [u8; 32] = hash_output_slice.try_into()
                    .expect("Slice with incorrect length");
                selected_hash_function().hash_h(hash_output_array, &pk[..kyber_public]);
            } else {
                // Handle error: slice is not long enough
                return Err(());
            }

            {
                let mut rng = crate::GLOBAL_RANDOM.lock().unwrap();
                let mut temp_vec = vec![0u8; kyber_sym as usize];
                rng.randombytes(&mut temp_vec, kyber_sym as u64);
                sk[kyber_secret - kyber_sym..kyber_secret].copy_from_slice(&temp_vec);
            }
            
            

             return Ok(());


            }
    pub fn crypto_kem_enc( ct: &mut Vec<u8>, ss: &mut Vec<u8>, pk: &mut Vec<u8>) -> Result<(), ()> {
        
            let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();
            let kyber_ciphertextbytes:usize = crate::get_env_var("KYBER_CIPHERTEXTBYTES").unwrap();

            let hash_function = selected_hash_function();

            let mut buf = vec![0u8; 2 * kyber_symbytes];
            let mut kr = vec![0u8; 2 * kyber_symbytes];

            // Generate random data into buf

            {
                let mut rng = crate::GLOBAL_RANDOM.lock().unwrap();
                rng.randombytes(&mut buf, kyber_symbytes as u64);
            }


            // Hash buf (first half) and store the result in the same buffer
            let mut buf_array_32: [u8; 32] = buf[..32].try_into().expect("Slice with incorrect length");
            hash_function.hash_h(&mut buf_array_32, &buf[..kyber_symbytes]);
            buf[..32].copy_from_slice(&buf_array_32);

            // Multitarget countermeasure for coins + contributory KEM
            // Hash buf (second half) and store the result in the same buffer
            let mut buf_array_32_second: [u8; 32] = buf[kyber_symbytes..kyber_symbytes + 32].try_into().expect("Slice with incorrect length");
            hash_function.hash_h(&mut buf_array_32_second, pk);
            buf[kyber_symbytes..kyber_symbytes + 32].copy_from_slice(&buf_array_32_second);

            // Resize kr to 64 bytes for hash_g and create a mutable reference
            kr.resize(64, 0);
            let kr_array_64: &mut [u8; 64] = kr.as_mut_slice().try_into().expect("Slice with incorrect length");
            hash_function.hash_g(kr_array_64, &buf);

            // coins are in kr+kyber_symbytes
            crate::indcpa::indcpa::indcpa_enc(ct, &buf, pk, &kr[kyber_symbytes..]);

            // Overwrite coins in kr with H(c)
            let mut hash_output: [u8; 32] = [0; 32];
            hash_function.hash_h(&mut hash_output, ct);
            
            // Copy the hash result back into `kr` starting at KYBER_SYMBYTES
            kr[kyber_symbytes..kyber_symbytes + 32].copy_from_slice(&hash_output);
            

            // Hash concatenation of pre-k and H(c) to k
            if ss.len() < 32 {
                return Err(());
            }

            // Convert the first 32 bytes of ss into a mutable array reference
            let ss_array_32: &mut [u8; 32] = {
                let ptr = ss.as_mut_ptr() as *mut [u8; 32];
                unsafe { &mut *ptr }
            };


            hash_function.kdf(ss_array_32, &kr);

            return Ok(());
    }



    pub fn crypto_kem_dec(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> Result<(), ()> {
        let kyber_i_secret: usize = crate::get_env_var("KYBER_INDCPA_SECRETKEYBYTES").unwrap();
        let kyber_cipher: usize = crate::get_env_var("KYBER_CIPHERTEXTBYTES").unwrap();
        let kyber_secret: usize = crate::get_env_var("KYBER_SECRETKEYBYTES").unwrap();
        let kyber_symbytes: usize = crate::get_env_var("KYBER_SYMBYTES").unwrap();

            let hash_function = selected_hash_function();
            let mut buf = vec![0u8; 2 * kyber_symbytes];
            let mut kr = vec![0u8; 2 * kyber_symbytes];
            let mut cmp = vec![0u8; kyber_cipher];
            let pk = &sk[kyber_i_secret..];


            // Create a mutable reference to the entire vector as &[u8; 64]
            let mut kr_whole: &mut [u8; 64] = kr.as_mut_slice().try_into().expect("Slice with incorrect length");


                        // Call the indcpa_dec function
            crate::indcpa::indcpa::indcpa_dec(&mut buf, ct, sk);

            // Multitarget countermeasure for coins + contributory KEM
            for i in 0..kyber_symbytes {
                buf[kyber_symbytes + i] = sk[kyber_secret - 2 * kyber_symbytes + i];
            }


            // Hash buf and store the result in kr
            hash_function.hash_g(&mut kr_whole, &buf);

            // Create arrays with non-constant values
            let mut kr_half1_array: [u8; 32] = Default::default();
            let mut kr_half2_array: [u8; 32] = Default::default();

            // Create mutable references to the arrays
            let kr_half1: &mut [u8; 32] = &mut kr_half1_array;
            let kr_half2: &mut [u8; 32] = &mut kr_half2_array;

            // Copy elements from kr_whole into kr_half1 and kr_half2
            kr_half1.copy_from_slice(&kr_whole[..32]);
            kr_half2.copy_from_slice(&kr_whole[32..]);
            
            // coins are in kr+kyber_symbytes
            crate::indcpa::indcpa::indcpa_enc(&mut cmp, &buf, pk, kr_half2);


            // Verify ct and cmp
            let fail = crate::verify::verify::verify(ct, &cmp, kyber_cipher);

            // Overwrite coins in kr with the hash of ct
            hash_function.hash_h(kr_half2, ct);


            // Conditionally overwrite pre-k with z on re-encryption failure
            let fail_u8 = if fail != 0 { 1 } else { 0 };

            for (i, &val) in kr_half2.iter().enumerate() {
                kr_whole[i + kyber_symbytes] = val;
            }
            crate::verify::verify::cmov(kr_whole, &sk[kyber_secret - kyber_symbytes..], kyber_symbytes, fail_u8);

            // Hash concatenation of pre-k and H(c) to k

            if ss.len() < 32 {
                // Handle error: ss is not long enough
                return Err(());
            }

            // Convert the first 32 bytes of ss into a mutable array reference
            let ss_array_32: &mut [u8; 32] = {
                let ptr = ss.as_mut_ptr() as *mut [u8; 32];
                unsafe { &mut *ptr }
            };

            // Hash concatenation of pre-k and H(c) to k
            hash_function.kdf(ss_array_32, kr_whole);

        Ok(())
    }


}
