#![allow(warnings)]
use std::{env, u8};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::io;
use libloading::{Library, Symbol};
extern crate  pkg_config;
mod library_loading;
use std::ptr;
extern crate lazy_static;


extern crate sha2;
use std::sync::Mutex;
use std::fs::File;
use std::io::{BufRead, Read};
use std::io::{Write};
mod kem;
mod kyber;
mod rng;
mod xof_state;
mod kyber_rng;
mod speed_print;
mod helping_functions;
mod config;
mod fips202;
mod indcpa;
mod aes256ctr;
mod symmetric_aes;
mod polyvec;
mod verify;
mod poly_struct;
mod polyvec_struct;
mod poly;
mod cbd;
mod reduce;
mod ntt;
mod symmetric_shake;
use tick_counter::TickCounter;

fn main() {


    library_loading::load_library("/home/adam/Documents/random/CRandomForRust/src/c_library/rustRng.so");
    // Now you can use the globally accessible functions 
    let mut entropy_input: [u8; 48] = [0; 48];
    for i in 0..48 {
        entropy_input[i] = i as u8;
    }
    
    unsafe {
        library_loading::call_randombytes_init(entropy_input.as_mut_ptr(), ptr::null(), 256);
        let mut buffer = vec![0u8; 10]; // Example buffer
        library_loading::call_randombytes(buffer.as_mut_ptr(), buffer.len() as u64);
    }
   
    println!("Welcome to Kyber Encryption");
        println!("Please enter the security strength, you can always adjust it later.");
        let strength: u32 = helping_functions::helping_functions::get_security_strength();
        let mut kyber = kyber::Kyber::create(strength);
        println!("Running some tests...");
 set_env_vars(kyber.params.clone());
        println!("Please enter the seed value:");
        let seed = helping_functions::helping_functions::get_seed_input();

        let seed_ptr = seed.as_ptr();
        let ps: u8 = 0; 
        let seed_test: Vec<u8> = [1u8; 48].to_vec();
        let mut private_key = vec![0u8; kyber.params.kyber_secretkeybytes as usize];
        let mut public_key = vec![0u8; kyber.params.kyber_publickeybytes as usize];
        let tick_counter = TickCounter::current();
        let mut kr = crate::kyber_rng::KyberRng::new();
        kr.randombytes_init(seed_test, None, 256);
        let mut x: Vec<u8> = vec![0u8; 48];
        let p = x.len();
        println!("Some random {:?}", kr.randombytes(&mut x, p as u64));
        kem::kem::crypto_kem_keypair(&mut public_key, &mut private_key).expect("Key pair generation failed");

    
        println!("Public Key: {:?}", public_key);
        println!("Private Key: {:?}", private_key);
        let elapsed_ticks = tick_counter.elapsed();
println!("Number of elapsed ticks: {}", elapsed_ticks);

    //confirmed!
    // Print the generated random bytes
}

pub fn set_env_vars(params: kyber::KyberParams)
{
    env::set_var("KYBER_K", params.kyber_k.to_string());
    env::set_var("KYBER_90S", "false");
    env::set_var("KYBER_NAMESPACE", params.kyber_namespace);
    env::set_var("KYBER_N", params.kyber_n.to_string());
    env::set_var("KYBER_Q", params.kyber_q.to_string());
    env::set_var("KYBER_SYMBYTES", params.kyber_symbytes.to_string());
    env::set_var("KYBER_SSBYTES", params.kyber_ssbytes.to_string());
    env::set_var("KYBER_POLYBYTES", params.kyber_polybytes.to_string());
    env::set_var("KYBER_POLYCOMPRESSEDBYTES", params.kyber_polycompressedbytes.to_string());
    env::set_var("KYBER_POLYVECBYTES", params.kyber_polyvecbytes.to_string());
    env::set_var("KYBER_ETA1", params.kyber_eta1.to_string());
    env::set_var("KYBER_POLYVECCOMPRESSEDBYTES", params.kyber_polyveccompressedbytes.to_string());
    env::set_var("KYBER_ETA2", params.kyber_eta2.to_string());
    env::set_var("KYBER_INDCPA_MSGBYTES", params.kyber_indcpa_msgbytes.to_string());
    env::set_var("KYBER_INDCPA_PUBLICKEYBYTES", params.kyber_indcpa_publickeybytes.to_string());
    env::set_var("KYBER_INDCPA_SECRETKEYBYTES", params.kyber_indcpa_secretkeybytes.to_string());
    env::set_var("KYBER_INDCPA_BYTES", params.kyber_indcpa_bytes.to_string());
    env::set_var("KYBER_PUBLICKEYBYTES", params.kyber_publickeybytes.to_string());
    env::set_var("KYBER_SECRETKEYBYTES", params.kyber_secretkeybytes.to_string());
    env::set_var("KYBER_CIPHERTEXTBYTES", params.kyber_ciphertextbytes.to_string());
}

pub fn get_env_var<T>(name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    match env::var(name) {
        Ok(value) => match value.parse() {
            Ok(parsed) => Ok(parsed),
            Err(err) => Err(format!("Failed to parse {}: {:?}", name, err)),
        },
        Err(_) => Err(format!("{} environment variable not set", name)),
    }
}
