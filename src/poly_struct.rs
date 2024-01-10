use std::env;

#[derive(Clone)]
pub struct PolyStruct {
    pub coeffs: Vec<i16>,
}

impl PolyStruct {
    pub fn new() -> Self {
        let kyber_n: usize = match env::var("KYBER_N") {
            Ok(val) => val.parse().expect("Invalid KYBER_N value"),
            Err(_) => 0, // Default value if environment variable is not set
        };

        PolyStruct {
            coeffs: vec![0; kyber_n], // Set the size of coeffs to kyber_n
        }
    }
}
