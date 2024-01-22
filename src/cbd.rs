use std::convert::TryInto;
pub mod cbd
{
    use std::env;

    pub fn test()
    {
        println!("test");
    }
    pub fn load32_littleendian(x: &[u8]) -> u32 {
        u32::from_le_bytes(x.try_into().unwrap())
    }

    pub fn cbd2(r: &mut crate::poly_struct::PolyStruct, buf: &[u8]) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
        for i in 0..kyber_n / 8 {
            let t = load32_littleendian(&buf[(4 * i) as usize..(4 * (i + 1)) as usize]);
            let d = t & 0x55555555;
            let d = d + ((t >> 1) & 0x55555555);
    
            for j in 0..8 {
                let a = ((d >> (4 * j)) & 0x3) as i16;
                let b = ((d >> (4 * j + 2)) & 0x3) as i16;
                r.coeffs[(8 * i + j) as usize] = a - b;
            }
        }
    }
    

    pub fn load24_littleendian(x: &[u8]) -> u32 {
        (x[0] as u32) | ((x[1] as u32) << 8) | ((x[2] as u32) << 16)
    }


    pub fn cbd3(r: &mut crate::poly_struct::PolyStruct, buf: &[u8]) {
        let kyber_n: u32 = crate::get_env_var("KYBER_N").unwrap();
            for i in 0..kyber_n / 4 {
                let t = load24_littleendian(&buf[(3 * i) as usize..]);

                let d = t & 0x00249249;
                let d = d + ((t >> 1) & 0x00249249);
                let d = d + ((t >> 2) & 0x00249249);

                for j in 0..4 {
                    let a = ((d >> (6 * j)) & 0x7) as i16;
                    let b = ((d >> (6 * j + 3)) & 0x7) as i16;
                    r.coeffs[(4 * i + j) as usize] = a - b;
                }
            }
        
    }

    pub fn cbd_eta1(r: &mut crate::poly_struct::PolyStruct, buf: &[u8]) { // had ; kyber_eta1 * kyber_n / 4]
        let kyber_eta1: u32 = crate::get_env_var("KYBER_ETA1").unwrap();
            if kyber_eta1 == 2
            {
                cbd2(r, buf);
            }
            else if kyber_eta1 == 3
            {
                cbd3(r, buf);
            }
        

    }

    pub fn cbd_eta2(r: &mut crate::poly_struct::PolyStruct, buf: &[u8]) { // was  kyber_eta2 * kyber_n / 4
        let kyber_eta2: u32 = crate::get_env_var("KYBER_ETA2").unwrap();
            if kyber_eta2 == 2
            {
                cbd2(r, buf);
            }

        }
    
}