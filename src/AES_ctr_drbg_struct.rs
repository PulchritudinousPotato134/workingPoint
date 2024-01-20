use std::os::raw::c_uchar;

struct AES256_CTR_DRBG_struct
{
    Key: [c_uchar; 32],
    V: [c_uchar; 16],
    reeseed_couter: u32

}