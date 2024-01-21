#![allow(warnings)]
use std::{env, u8};
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;
use std::io;
use libloading::{Library, Symbol};
extern crate  pkg_config;
use std::ptr;
use lazy_static::lazy_static;

extern crate sha2;
use std::sync::Mutex;
use std::fs::File;
use std::io::{BufRead, Read};
use std::io::{Write};
mod kem;
mod kyber;
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


lazy_static! {
    static ref GLOBAL_RANDOM: Mutex<kyber_rng::KyberRng> = Mutex::new(kyber_rng::KyberRng::new());
}

fn main() {

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
        let hex_string = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";


        let test_bytes = hex::decode(hex_string).expect("Woops, it blew up");
        // Convert the hexadecimal string to bytes
        let bytes = hex::decode(hex_string).expect("Failed to decode hexadecimal string");

        // Create a Vec<u8> from the bytes
        
        let mut private_key = vec![0u8; kyber.params.kyber_secretkeybytes as usize];
        let mut public_key = vec![0u8; kyber.params.kyber_publickeybytes as usize];

        {
            let mut rng = GLOBAL_RANDOM.lock().unwrap();
            rng.randombytes_init(test_bytes, None, 256);
        }
        
        let mut x: Vec<u8> = vec![0u8; 48];
        let p = x.len();
        kem::kem::crypto_kem_keypair(&mut public_key, &mut private_key).expect("Key pair generation failed");

    
        println!("Public Key: {:?}", hex::encode(public_key));
        println!("Private Key: {:?}", hex::encode(private_key));

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
