#[link(name = "rngForRust")]
extern crate libc;

use libc::{c_char, c_int, c_ulonglong, c_void};

#[repr(C)]
pub struct AES_XOF_struct {
    buffer: [u8; 16],
    buffer_pos: c_int,
    length_remaining: c_ulonglong,
    key: [u8; 32],
    ctr: [u8; 16],
}

#[repr(C)]
pub struct AES256_CTR_DRBG_struct {
    Key: [u8; 32],
    V: [u8; 16],
    reseed_counter: c_int,
}

extern {
    pub fn AES256_CTR_DRBG_Update(provided_data: *const u8, Key: *mut u8, V: *mut u8);
    pub fn seedexpander_init(ctx: *mut AES_XOF_struct, seed: *const u8, diversifier: *const u8, maxlen: c_ulonglong) -> c_int;
    pub fn seedexpander(ctx: *mut AES_XOF_struct, x: *mut u8, xlen: c_ulonglong) -> c_int;
    pub fn randombytes_init(entropy_input: *const u8, personalization_string: *const u8, security_strength: c_int);
    pub fn randombytes(x: *mut u8, xlen: c_ulonglong);
}

pub struct Rng {
    pub xof: AES_XOF_struct,
    pub drbg: AES256_CTR_DRBG_struct,
}

impl Rng {
    pub fn new() -> Self {
        // Initialize your rng struct here if needed
        Rng {
            xof: AES_XOF_struct {
                buffer: [0; 16],
                buffer_pos: 0,
                length_remaining: 0,
                key: [0; 32],
                ctr: [0; 16],
            },
            drbg: AES256_CTR_DRBG_struct {
                Key: [0; 32],
                V: [0; 16],
                reseed_counter: 0,
            },
        }
    }

    pub fn update(&mut self, provided_data: *const u8, key: *mut u8, v: *mut u8) {
        unsafe {
            AES256_CTR_DRBG_Update(provided_data, key, v);
        }
        // You can update the state of the rng struct here
    }

    pub fn seedexpander_init(&mut self, seed: *const u8, diversifier: *const u8, maxlen: c_ulonglong) -> c_int {
        unsafe {
            seedexpander_init(&mut self.xof, seed, diversifier, maxlen)
        }
    }

    pub fn seedexpander(&mut self, x: *mut u8, xlen: c_ulonglong) -> c_int {
        unsafe {
            seedexpander(&mut self.xof, x, xlen)
        }
    }

    pub fn randombytes_init(&mut self, entropy_input: *const u8, personalization_string: *const u8, security_strength: c_int) {
        unsafe {
            randombytes_init(entropy_input, personalization_string, security_strength);
        }
    }

    pub fn randombytes(&mut self, x: *mut u8, xlen: c_ulonglong) {
        unsafe {
            randombytes(x, xlen);
        }
    }
}
