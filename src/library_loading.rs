use std::{sync::Mutex};
use lazy_static::lazy_static;
use libc::XDP_UMEM_COMPLETION_RING;
use libloading::{Library, Symbol};
use std::ffi::OsStr;

// Define function types
type RandomBytesInitFn = unsafe extern "C" fn(*const u8, *const u8, u64);
type RandomBytesFn = unsafe extern "C" fn(*mut u8, u64);

lazy_static! {
    static ref LIBRARY: Mutex<Option<Library>> = Mutex::new(None);
    static ref RANDOMBYTES_INIT: Mutex<Option<RandomBytesInitFn>> = Mutex::new(None);
    static ref RANDOMBYTES: Mutex<Option<RandomBytesFn>> = Mutex::new(None);
}

pub fn load_library<P: AsRef<OsStr>>(path: P) {
    unsafe{
    let lib = Library::new(path).expect("Failed to load C library");
    let mut lib_guard = LIBRARY.lock().unwrap();
    *lib_guard = Some(lib);
 
        let randombytes_init: Symbol<RandomBytesInitFn> = lib_guard.as_ref().unwrap().get(b"randombytes_init\0").expect("Failed to get randombytes_init");
        let randombytes: Symbol<RandomBytesFn> = lib_guard.as_ref().unwrap().get(b"randombytes\0").expect("Failed to get randombytes");

        *RANDOMBYTES_INIT.lock().unwrap() = Some(*randombytes_init);
        *RANDOMBYTES.lock().unwrap() = Some(*randombytes);
    }
}

pub unsafe fn call_randombytes_init(entropy_input: *const u8, personalization_string: *const u8, security_strength: u64) {
    if let Some(func) = *RANDOMBYTES_INIT.lock().unwrap() {
        func(entropy_input, personalization_string, security_strength);
    } else {
        panic!("randombytes_init function not loaded");
    }
}

pub unsafe fn call_randombytes(x: *mut u8, xlen: u64) {
    if let Some(func) = *RANDOMBYTES.lock().unwrap() {
        //func(x, xlen);
        for i in 0..xlen {
            *x.offset(i as isize) = 1;
        }
    } else {
        panic!("randombytes function not loaded");
    }
}
