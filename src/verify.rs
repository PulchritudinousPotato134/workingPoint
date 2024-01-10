
pub mod verify{
    /*************************************************
    * Name:        verify
    *
    * Description: Compare two arrays for equality in constant time.
    *
    * Arguments:   const uint8_t *a: pointer to first byte array
    *              const uint8_t *b: pointer to second byte array
    *              size_t len:       length of the byte arrays
    *
    * Returns 0 if the byte arrays are equal, 1 otherwise
    **************************************************/
    pub fn verify(a: &[u8], b: &[u8], len: usize) -> u64 {
        let mut r: u8 = 0;

        for i in 0..len {
            r |= a[i] ^ b[i];
        }

        (-(r as i8) as u64) >> 63
    }


    /*************************************************
    * Name:        cmov
    *
    * Description: Copy len bytes from x to r if b is 1;
    *              don't modify x if b is 0. Requires b to be in {0,1};
    *              assumes two's complement representation of negative integers.
    *              Runs in constant time.
    *
    * Arguments:   uint8_t *r:       pointer to output byte array
    *              const uint8_t *x: pointer to input byte array
    *              size_t len:       Amount of bytes to be copied
    *              uint8_t b:        Condition bit; has to be in {0,1}
    **************************************************/
    pub fn cmov(r: &mut [u8], x: &[u8], len: usize, b: u8) {
        let mut b = -((b as i8) as i32) as u8;

        for i in 0..len {
            r[i] ^= b & (r[i] ^ x[i]);
        }
    }
}