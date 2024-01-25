

use std::fs::File;
use std::io::Write;

use openssl::error::ErrorStack;
use openssl::symm::{Cipher, Crypter, Mode};
#[derive(Clone)]
pub struct AesXofStruct {
    length_remaining: u64,
    key: Vec<u8>,
    ctr: Vec<u8>,
    buffer_pos: u64,
    buffer: Vec<u8>,
}

#[derive(Clone)]
pub struct AES256_CTR_DRBG_struct {
    V: Vec<u8>,
    reseed_counter: u64,
    Key: Vec<u8>,
}
impl AES256_CTR_DRBG_struct 
{
    // Initialize the DRBG struct with the appropriate sizes for V and Key
    pub fn new() -> Self {
        AES256_CTR_DRBG_struct {
            V: vec![0u8; 16], 
            Key: vec![0u8; 32],
            reseed_counter: 0,
        }
    }
}

#[derive(Clone)]
pub struct KyberRng {
    drbg_ctx: AES256_CTR_DRBG_struct,
    rng_success: i32,
    rng_bad_maxlen: i32,
    rng_bad_outbuf: i32,
    rng_bad_req_len: i32,
}

impl KyberRng {
    pub fn new() -> Self {
        KyberRng {
            drbg_ctx: AES256_CTR_DRBG_struct {
                Key: vec![0u8; 32],
                V: vec![0u8; 16],
                reseed_counter: 0
            },
            rng_success: 0,
            rng_bad_maxlen: -1,
            rng_bad_outbuf: -2,
            rng_bad_req_len: -3,
        }
    }
    pub fn randombytes_init(&mut self, entropy_input: Vec<u8>, personalization_string: Option<Vec<u8>>, security_strength: u32) {
        let mut seed_material: Vec<u8> = vec![0; 48];

        seed_material[..entropy_input.len()].copy_from_slice(&entropy_input);

        if let Some(p_string) = personalization_string {
            for (i, &val) in p_string.iter().enumerate() {
                if i < seed_material.len() {
                    seed_material[i] ^= val;
                }
            }
        }

        
        self.drbg_ctx.Key = vec![0; 32];

     
        self.drbg_ctx.V = vec![0; 16];

        Self::AES256_CTR_DRBG_Update(Some(&seed_material), &mut self.drbg_ctx.Key, &mut self.drbg_ctx.V);
        self.drbg_ctx.reseed_counter = 1;
    }

    pub fn randombytes(&mut self, x: &mut Vec<u8>, mut xlen: u64) -> Result<(), &'static str> {
        let mut block: Vec<u8> = vec![0; 16];
        let mut i: usize = 0; 

        while xlen > 0 {
            for j in (0..=15).rev() {
                if self.drbg_ctx.V[j] == 0xff {
                    self.drbg_ctx.V[j] = 0x00;
                } else {
                    self.drbg_ctx.V[j] += 1;
                    break;
                }
            }

            Self::aes256_ecb(&self.drbg_ctx.Key, &self.drbg_ctx.V, &mut block);

            if xlen > 15 {
                let end_index = i + 16;
                if end_index > x.len() {
                    return Err("Buffer overflow");
                }
                x[i..end_index].copy_from_slice(&block);
                i += 16;
                xlen -= 16;
            } else {
                let end_index = i + xlen as usize;
                if end_index > x.len() {
                    return Err("Buffer overflow");
                }
                x[i..end_index].copy_from_slice(&block[..xlen as usize]);
                xlen = 0;
            }
        }

        Self::AES256_CTR_DRBG_Update(None, &mut self.drbg_ctx.Key, &mut self.drbg_ctx.V);
        self.drbg_ctx.reseed_counter += 1;


        Ok(())
    }

    pub fn AES256_CTR_DRBG_Update(provided_data: Option<&Vec<u8>>, Key: &mut Vec<u8>, V: &mut Vec<u8>) -> Result<(), &'static str> {
        let mut temp: Vec<u8> = vec![0; 48];
    
        for i in 0..3 {
            // Increment V
            for j in (0..16).rev() {
                if V[j] == 0xff {
                    V[j] = 0x00;
                } else {
                    V[j] += 1;
                    break;
                }
            }
    
            let block_start = i * 16;
            let block_end = block_start + 16;
            Self::aes256_ecb(Key, V, &mut temp[block_start..block_end]);
        }
    
        if let Some(data) = provided_data {
            for i in 0..48 {
                temp[i] ^= data[i];
            }
        }
    
        Key.copy_from_slice(&temp[..32]);
        V.copy_from_slice(&temp[32..]);
        Ok(())
    }
    
    pub fn aes256_ecb(key: &[u8], ctr: &[u8], buffer: &mut [u8]) -> Result<(), ErrorStack> {
        if key.len() != 32 {
            return Err(ErrorStack::get());
        }
    
        let cipher = Cipher::aes_256_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None)?;
        crypter.pad(false);
    
        let mut temp_buffer = vec![0; buffer.len() + cipher.block_size()];
        let count = crypter.update(ctr, &mut temp_buffer)?;
        let rest = crypter.finalize(&mut temp_buffer[count..])?;
        temp_buffer.truncate(count + rest);
    
        buffer.copy_from_slice(&temp_buffer);
    
    
        Ok(())
    }
    
    

    fn seedexpander_init(
        ctx: &mut AesXofStruct,
        seed: &Vec<u8>,
        diversifier: &Vec<u8>,
        maxlen: u32,
    ) -> Result<(), &'static str> {
       

        ctx.length_remaining = maxlen as u64;

        ctx.key[..32].copy_from_slice(seed);

        ctx.ctr[..8].copy_from_slice(&diversifier[..8]);
        ctx.ctr[11] = (maxlen % 256) as u8;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[10] = (maxlen % 256) as u8;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[9] = (maxlen % 256) as u8;
        let mut maxlen = maxlen >> 8;
        ctx.ctr[8] = (maxlen % 256) as u8;
        ctx.ctr[12..].fill(0x00);

        ctx.buffer_pos = 16;
        ctx.buffer.fill(0x00);

        Ok(())
    }

    fn seedexpander(ctx: &mut AesXofStruct , x: &mut Vec<u8>, mut xlen: usize) -> Result<(), &'static str> {
        if x.is_empty() {
            return Err("RNG_BAD_OUTBUF");
        }
        if xlen >= ctx.length_remaining as usize {
            return Err("RNG_BAD_REQ_LEN");
        }

        ctx.length_remaining -= xlen as u64;
        let mut offset = 0;

        while xlen > 0 {
            if xlen <= (16 - ctx.buffer_pos as usize) {
                x[offset..(offset + xlen)].copy_from_slice(&ctx.buffer[ctx.buffer_pos as usize..(ctx.buffer_pos as usize + xlen)]);
                ctx.buffer_pos += xlen as u64;
                return Ok(());
            }

            x[offset..(offset + (16 - ctx.buffer_pos as usize))]
                .copy_from_slice(&ctx.buffer[ctx.buffer_pos as usize..16]);
            xlen -= 16 - ctx.buffer_pos as usize;
            offset += 16 - ctx.buffer_pos as usize;

            Self::aes256_ecb(&mut ctx.key, &mut ctx.ctr, &mut ctx.buffer);
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

}