/*use std::ffi::c_uchar;
use openssl;

use crate::rng_from_c::AES256_CTR_DRBG_struct;
pub struct rng {
    DRBG_ctx: AES256_CTR_DRBG_struct
}

    impl rng{
        pub fn randombytes_init(entropy_input: &[c_uchar], personalization_string: &[c_uchar], security_strength: u32) {
            let mut seed_material: [c_uchar; 48] = [0; 48];
            
            seed_material[..entropy_input.len()].copy_from_slice(entropy_input);

            if let Some(index) = personalization_string.iter().position(|&x| x != 0) {
                for i in index..48 {
                    seed_material[i] ^= personalization_string[i];
                }
                
                // Set DRBG_ctx.Key to 0x00 for 32 bytes
                DRBG_ctx.Key = [0; 32];

                // Set DRBG_ctx.V to 0x00 for 16 bytes
                DRBG_ctx.V = [0; 16];
                
                AES256_CTR_DRBG_Update(&seed_material, &mut DRBG_ctx.Key, &mut DRBG_ctx.V);
                DRBG_ctx.reseed_counter = 1;
            }
        }
    }

    pub fn randombytes(x: &mut [c_uchar], mut xlen: u64) {
        let mut block: [c_uchar; 16] = [0; 16];
        let mut i: i32 = 0;

        while xlen > 0 {
            // Increment V
            for j in (0..=15).rev() {
                if DRBG_ctx.V[j] == 0xff {
                    DRBG_ctx.V[j] = 0x00;
                } else {
                    DRBG_ctx.V[j] += 1;
                    break;
                }
            }

            AES256_ECB(&DRBG_ctx.Key, &DRBG_ctx.V, &mut block);

            if xlen > 15 {
                x[i..(i + 16)].copy_from_slice(&block);
                i += 16;
                xlen -= 16;
            } else {
                x[i..(i + xlen as usize)].copy_from_slice(&block[..xlen as usize]);
                xlen = 0;
            }
        }

        AES256_CTR_DRBG_Update(None, &mut DRBG_ctx.Key, &mut DRBG_ctx.V);
        DRBG_ctx.reseed_counter += 1;

        for elem in x.iter_mut() {
            *elem = 1;
        }
    }

    pub fn AES256_CTR_DRBG_Update(provided_data: Option<&[c_uchar]>, Key: &mut [c_uchar], V: &mut [c_uchar]) {
        let mut temp: [c_uchar; 48] = [0; 48];

        for _ in 0..3 {
            // Increment V
            for j in (0..=15).rev() {
                if V[j] == 0xff {
                    V[j] = 0x00;
                } else {
                    V[j] += 1;
                    break;
                }
            }

            AES256_ECB(Key, V, &mut temp);
        }

        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }

        Key.copy_from_slice(&temp[..32]);
        V.copy_from_slice(&temp[32..]);
    }

    pub fn AES256_ECB(key: &[c_uchar], ctr: &[c_uchar], buffer: &mut [c_uchar]) -> Result<(), &'static str> {
        // Create and initialize the context
        let cipher = openssl::symm::Cipher::aes_256_ecb();
        let mut ctx = openssl::symm::Crypter::new(cipher, openssl::symm::Mode::Encrypt, key, None)?;

        // Encrypt the data
        let len = ctx.update(ctr, buffer)?;

        // Clean up
        ctx.finalize(&mut buffer[len..])?;

        // Rest of your code here

        Ok(())
    }

    fn seedexpander_init(
        ctx: &mut AES_XOF_struct,
        seed: &[c_uchar],
        diversifier: &[c_uchar],
        maxlen: u32,
    ) -> Result<(), &'static str> {
        if maxlen >= 0x100000000 {
            return Err("RNG_BAD_MAXLEN");
        }

        ctx.length_remaining = maxlen;

        ctx.key[..32].copy_from_slice(seed);

        ctx.ctr[..8].copy_from_slice(&diversifier[..8]);
        ctx.ctr[11] = (maxlen % 256) as c_uchar;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[10] = (maxlen % 256) as c_uchar;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[9] = (maxlen % 256) as c_uchar;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[8] = (maxlen % 256) as c_uchar;
        ctx.ctr[12..].fill(0x00);

        ctx.buffer_pos = 16;
        ctx.buffer.fill(0x00);

        Ok(())
    }

    fn seedexpander(ctx: &mut AES_XOF_struct, x: &mut [c_uchar], xlen: usize) -> Result<(), &'static str> {
        if x.is_empty() {
            return Err("RNG_BAD_OUTBUF");
        }
        if xlen >= ctx.length_remaining as usize {
            return Err("RNG_BAD_REQ_LEN");
        }

        ctx.length_remaining -= xlen as u32;
        let mut offset = 0;

        while xlen > 0 {
            if xlen <= (16 - ctx.buffer_pos) {
                x[offset..(offset + xlen)].copy_from_slice(&ctx.buffer[ctx.buffer_pos..(ctx.buffer_pos + xlen)]);
                ctx.buffer_pos += xlen;
                return Ok(());
            }

            x[offset..(offset + (16 - ctx.buffer_pos))]
                .copy_from_slice(&ctx.buffer[ctx.buffer_pos..16]);
            xlen -= 16 - ctx.buffer_pos;
            offset += 16 - ctx.buffer_pos;

            AES256_ECB(&mut ctx.key, &mut ctx.ctr, &mut ctx.buffer);
            ctx.buffer_pos = 0;

            for i in (12..=15).rev() {
                if ctx.ctr[i] == 0xff {
                    ctx.ctr[i] = 0x00;
                } else {
                    ctx.ctr[i] += 1;
                    break;
                }
            }
        }

        Ok(())
    }
*/