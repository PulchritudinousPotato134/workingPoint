pub mod reduce
{
    /*************************************************
* Name:        montgomery_reduce
*
* Description: Montgomery reduction; given a 32-bit integer a, computes
*              16-bit integer congruent to a * R^-1 mod q,
*              where R=2^16
*
* Arguments:   - int32_t a: input integer to be reduced;
*                           has to be in {-q2^15,...,q2^15-1}
*
* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
**************************************************/
    pub fn montgomery_reduce(a: i32) -> i16 {
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            let mut t: i32;
            let mut u: i32;

            u = a * 62209; //QINV;
            t = (u) * kyber_q as i32;
            t = a - t;
            t >>= 16;

           return t as i16

    }

    /*************************************************
* Name:        barrett_reduce
*
* Description: Barrett reduction; given a 16-bit integer a, computes
*              16-bit integer congruent to a mod q in {0,...,q}
*
* Arguments:   - int16_t a: input integer to be reduced
*
* Returns:     integer in {0,...,q} congruent to a modulo q.
**************************************************/
    pub fn barrett_reduce(a: i16) -> i16 {
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
        
            let v: i16 = ((1i32 << 26) + (kyber_q as i32/ 2) ) as i16;
            let mut t: i32;

            t = ((v as i32) * (a as i32)) >> 26;
            t *= kyber_q as i32;

            return a - t as i16;
      
    }


    /*************************************************
* Name:        csubq
*
* Description: Conditionallly subtract q
*
* Arguments:   - int16_t x: input integer
*
* Returns:     a - q if a >= q, else a
**************************************************/
    pub fn csubq(a: i16) -> i16 {
        
        let kyber_q: u32 = crate::get_env_var("KYBER_Q").unwrap();
            let mut a = a - kyber_q as i16;
            a += (a >> 15) & kyber_q as i16;
            return a; 
        }
    

}
