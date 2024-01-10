
use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
#[derive(Clone)]
pub struct AesXofStruct {
    length_remaining: u64,
    key: [u8; 32],
    ctr: [u8; 12],
    buffer_pos: u64,
    buffer: [u8; 16],
    v: [u8; 16],
    reseed_counter: u64,
}
#[derive(Clone)]
pub struct KyberRng {
    drbg_ctx: AesXofStruct,
    rng_success: i32,
    rng_bad_maxlen: i32,
    rng_bad_outbuf: i32,
    rng_bad_req_len: i32,
}

impl KyberRng {
    pub fn new() -> Self {
        KyberRng {
            drbg_ctx: AesXofStruct {
                length_remaining: 0,
                key: [0u8; 32],
                ctr: [0u8; 12],
                buffer_pos: 0,
                buffer: [0u8; 16],
                v: [0u8; 16],
                reseed_counter: 0,
            },
            rng_success: 0,
            rng_bad_maxlen: -1,
            rng_bad_outbuf: -2,
            rng_bad_req_len: -3,
        }
    }
    pub fn test()
    {
        println!("test");
    }

    pub fn seedexpander_init(&mut self, seed: &[u8; 32], diversifier: &[u8; 8], maxlen: u64) -> i32 {
        if maxlen >= 0x100000000 {
            return self.rng_bad_maxlen;
        }

        self.drbg_ctx.length_remaining = maxlen;
        self.drbg_ctx.key.copy_from_slice(seed);
        self.drbg_ctx.ctr[..8].copy_from_slice(diversifier);
        self.drbg_ctx.ctr[11] = (maxlen % 256) as u8;
        self.drbg_ctx.ctr[10] = ((maxlen >> 8) % 256) as u8;
        self.drbg_ctx.ctr[9] = ((maxlen >> 16) % 256) as u8;
        self.drbg_ctx.ctr[8] = ((maxlen >> 24) % 256) as u8;
        self.drbg_ctx.ctr[12..].fill(0x00);
        self.drbg_ctx.buffer_pos = 16;
        self.drbg_ctx.buffer.fill(0x00);

        self.rng_success
    }

    pub fn seedexpander(&mut self, x: &mut [u8], xlen: u64) -> i32 {
        if x.is_empty() {
            return self.rng_bad_outbuf;
        }
        if xlen >= self.drbg_ctx.length_remaining {
            return self.rng_bad_req_len;
        }

        self.drbg_ctx.length_remaining -= xlen;

        let mut offset: u64 = 0;
        let mut remaining = xlen; // Create a mutable local variable for the loop

        while remaining > 0 {
            let mut ctx = &mut self.drbg_ctx;
            let buffer_pos_usize = ctx.buffer_pos as usize;
            let offset_usize = offset as usize;
            let remaining_usize = remaining as usize;

            if remaining_usize <= 16 - buffer_pos_usize {
                // Buffer has what we need
                x[offset_usize..(offset_usize + remaining_usize)]
                    .copy_from_slice(&ctx.buffer[buffer_pos_usize..(buffer_pos_usize + remaining_usize)]);
                ctx.buffer_pos += remaining_usize as u64;

                return self.rng_success;
            }

            // Take what's in the buffer
            let buffer_available = 16 - ctx.buffer_pos as usize;
            x[offset_usize..(offset_usize + buffer_available)]
                .copy_from_slice(&ctx.buffer[ctx.buffer_pos as usize..][..buffer_available]);
            remaining -= buffer_available as u64;
            offset += buffer_available as u64;

            KyberRng::aes256_ecb(&mut self.drbg_ctx.key, &mut self.drbg_ctx.ctr, &mut self.drbg_ctx.buffer).expect("TODO: panic message");
            self.drbg_ctx.buffer_pos = 0;

            // Increment the counter
            for i in (8..=11).rev() {
                if self.drbg_ctx.ctr[i as usize] == 0xff {
                    self.drbg_ctx.ctr[i as usize] = 0x00;
                } else {
                    self.drbg_ctx.ctr[i as usize] += 1;
                    break;
                }
            }
        }

        self.rng_success
    }
  
    
    pub fn aes256_ecb(key: &[u8], ctr: &[u8], buffer: &mut [u8]) -> Result<(), ErrorStack> {
        let cipher = Cipher::aes_256_ecb();
        let mode = Mode::Encrypt;
        print!("Key: {}", key.len());
        print!(" ctr: {}", ctr.len());
        print!(" buffer: {}", buffer.len());
        
        // Ensure that the input slices have the correct lengths
        if key.len() != 32 || ctr.len() != 16 || buffer.len() != 16 {
            return Err(ErrorStack::get()); // Return an empty ErrorStack
        }
    
        let mut crypter = Crypter::new(cipher, mode, &key[..16], None)?; // Use the first 16 bytes of the key
        crypter.pad(false);
    
        crypter.update(ctr, buffer)?;
    
        crypter.finalize(buffer)?;
    
        Ok(())
    }
    
    pub fn randombytes_init(&mut self, entropy_input: &[u8], personalization_string: Option<&[u8]>) {
        let mut seed_material = [0u8; 48];
        seed_material[..48].copy_from_slice(&entropy_input[..48]);

        if let Some(ps) = personalization_string {
            for i in 0..48 {
                seed_material[i] ^= ps[i];
            }
        }

        // Temporarily replace key and v with empty arrays
        let mut temp_key = [0u8; 32];
        std::mem::swap(&mut temp_key, &mut self.drbg_ctx.key);
        let mut temp_v = [0u8; 16];
        std::mem::swap(&mut temp_v, &mut self.drbg_ctx.v);

        self.aes256_ctr_drbg_update(Some(&seed_material[..]), &mut temp_key, &mut temp_v);

        // Put the original key and v back
        std::mem::swap(&mut temp_key, &mut self.drbg_ctx.key);
        std::mem::swap(&mut temp_v, &mut self.drbg_ctx.v);

        self.drbg_ctx.reseed_counter = 1;
    }

    pub fn randombytes(&mut self, x: &mut [u8], mut xlen: u64) -> i32 {
        let mut block = [0u8; 16];
        let mut i = 0;

        while xlen > 0 {
            // Increment v
            for j in (0..=15).rev() {
                if self.drbg_ctx.v[j] == 0xff {
                    self.drbg_ctx.v[j] = 0x00;
                } else {
                    self.drbg_ctx.v[j] += 1;
                    break;
                }
            }

            KyberRng::aes256_ecb(&self.drbg_ctx.key, &self.drbg_ctx.v, &mut block).expect("AES256 ECB failed");

            let copy_len = std::cmp::min(xlen as usize, 16);
            x[i..i + copy_len].copy_from_slice(&block[..copy_len]);
            i += copy_len;
            xlen = xlen.saturating_sub(copy_len as u64);
        }

        // Temporarily swap out key and v
        let mut temp_key = [0u8; 32];
        let mut temp_v = [0u8; 16];
        std::mem::swap(&mut temp_key, &mut self.drbg_ctx.key);
        std::mem::swap(&mut temp_v, &mut self.drbg_ctx.v);

        KyberRng::aes256_ctr_drbg_update(self, None, &mut temp_key, &mut temp_v);

        // Swap back key and v
        std::mem::swap(&mut temp_key, &mut self.drbg_ctx.key);
        std::mem::swap(&mut temp_v, &mut self.drbg_ctx.v);

        self.drbg_ctx.reseed_counter += 1;

        self.rng_success
    }

pub fn aes256_ctr_drbg_update(&mut self, provided_data: Option<&[u8]>, key: &mut [u8], v: &mut [u8]) {
    let mut temp = [0u8; 48];

    for i in 0..3 {
        // Increment v
        for j in (0..=15).rev() {
            if v[j] == 0xff {
                v[j] = 0x00;
            } else {
                v[j] += 1;
                break;
            }
        }

        // Specify the correct range for the 16-byte block based on the iteration
        let block_start = i * 16;
        let block_end = block_start + 16;
        KyberRng::aes256_ecb(key, &v,&mut temp[block_start..block_end])
            .expect("TODO: panic message");
    }
    if let Some(pd) = provided_data {
        for i in 0..48 {
            temp[i] ^= pd[i];
        }
    }
    key[..32].copy_from_slice(&temp);
    v[..16].copy_from_slice(&temp[32..]);
}

}