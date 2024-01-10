use crate::poly_struct::PolyStruct;
use std::env;

#[derive(Clone)]
pub struct PolyVec {
    pub vec: Vec<PolyStruct>,
}

impl PolyVec {
    pub fn new() -> Self {
        let kyber_k: usize = match env::var("KYBER_K") {
            Ok(val) => val.parse().expect("Invalid KYBER_K value"),
            Err(_) => 0, // Default value if environment variable is not set
        };

        PolyVec {
            vec: (0..kyber_k).map(|_| PolyStruct::new()).collect(),
        }
    }
}
