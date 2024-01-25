pub mod aes256ctr {

    /*
     * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
     *
     * Permission is hereby granted, free of charge, to any person obtaining
     * a copy of this software and associated documentation files (the
     * "Software"), to deal in the Software without restriction, including
     * without limitation the rights to use, copy, modify, merge, publish,
     * distribute, sublicense, and/or sell copies of the Software, and to
     * permit persons to whom the Software is furnished to do so, subject to
     * the following conditions:
     *
     * The above copyright notice and this permission notice shall be
     * included in all copies or substantial portions of the Software.
     *
     * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
     * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
     * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
     * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
     * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
     * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
     * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
     * SOFTWARE.
     * 
     * Converted to Rust by Adam B
     */
    
    use std::convert::TryInto;
    
    pub fn test()
    {
        println!("test");
    }
    pub fn br_dec32le(src: &[u8]) -> u32 {
        u32::from_le_bytes(src.try_into().unwrap())
    }
    
    pub fn br_range_dec32le(v: &mut [u32], num: usize, src: &[u8]) {
        let mut src_idx = 0;
        for i in 0..num {
            v[i] = br_dec32le(&src[src_idx..src_idx + 4]);
            src_idx += 4;
        }
    }
    
    pub fn br_swap32(x: u32) -> u32 {
        ((x & 0x00FF00FF) << 8) | ((x >> 8) & 0x00FF00FF) | (x << 16) | (x >> 16)
    }
    
    pub fn br_enc32le(dst: &mut [u8; 4], x: u32) {
        dst[0] = x as u8;
        dst[1] = (x >> 8) as u8;
        dst[2] = (x >> 16) as u8;
        dst[3] = (x >> 24) as u8;
    }
    
    pub fn br_range_enc32le(dst: &mut [u8], v: &[u32], num: usize) {
        let mut dst_idx = 0;
        for i in 0..num {
            let mut enc_dst = [0u8; 4];
            br_enc32le(&mut enc_dst, v[i]);
            dst[dst_idx..dst_idx + 4].copy_from_slice(&enc_dst);
            dst_idx += 4;
        }
    }
    
    pub fn br_aes_ct64_bitslice_sbox(q: &mut [u64; 8]) {
        let (mut x0, mut x1, mut x2, mut x3, mut x4, mut x5, mut x6, mut x7) = (0, 0, 0, 0, 0, 0, 0, 0);
        let (mut y1, mut y2, mut y3, mut y4, mut y5, mut y6, mut y7, mut y8, mut y9) = (0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut y10, mut y11, mut y12, mut y13, mut y14, mut y15, mut y16, mut y17, mut y18, mut y19) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut y20, mut y21) = (0, 0);
        let (mut z0, mut z1, mut z2, mut z3, mut z4, mut z5, mut z6, mut z7, mut z8, mut z9) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut z10, mut z11, mut z12, mut z13, mut z14, mut z15, mut z16, mut z17) = (0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t0, mut t1, mut t2, mut t3, mut t4, mut t5, mut t6, mut t7, mut t8, mut t9) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t10, mut t11, mut t12, mut t13, mut t14, mut t15, mut t16, mut t17, mut t18, mut t19) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t20, mut t21, mut t22, mut t23, mut t24, mut t25, mut t26, mut t27, mut t28, mut t29) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t30, mut t31, mut t32, mut t33, mut t34, mut t35, mut t36, mut t37, mut t38, mut t39) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t40, mut t41, mut t42, mut t43, mut t44, mut t45, mut t46, mut t47, mut t48, mut t49) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t50, mut t51, mut t52, mut t53, mut t54, mut t55, mut t56, mut t57, mut t58, mut t59) = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        let (mut t60, mut t61, mut t62, mut t63, mut t64, mut t65, mut t66, mut t67) = (0, 0, 0, 0, 0, 0, 0, 0);
        let (mut s0, mut s1, mut s2, mut s3, mut s4, mut s5, mut s6, mut s7) = (0, 0, 0, 0, 0, 0, 0, 0);


        // Initialize x array
        x0 = q[7];
        x1 = q[6];
        x2 = q[5];
        x3 = q[4];
        x4 = q[3];
        x5 = q[2];
        x6 = q[1];
        x7 = q[0];
    
        // Top linear transformation
        y14 = x3 ^ x5;
        y13 = x0 ^ x6;
        y9 = x0 ^ x3;
        y8 = x0 ^ x5;
        t0 = x1 ^ x2;
        y1 = t0 ^ x7;
        y4 = y1 ^ x3;
        y12 = y13 ^ y14;
        y2 = y1 ^ x0;
        y5 = y1 ^ x6;
        y3 = y5 ^ y8;
        t1 = x4 ^ y12;
        y15 = t1 ^ x5;
        y20 = t1 ^ x1;
        y6 = y15 ^ x7;
        y10 = y15 ^ t0;
        y11 = y20 ^ y9;
        y7 = x7 ^ y11;
        y17 = y10 ^ y11;
        y19 = y10 ^ y8;
        y16 = t0 ^ y11;
        y21 = y13 ^ y16;
        y18 = x0 ^ y16;
    
        // Non-linear section
        t2 = y12 & y15;
        t3 = y3 & y6;
        t4 = t3 ^ t2;
        t5 = y4 & x7;
        t6 = t5 ^ t2;
        t7 = y13 & y16;
        t8 = y5 & y1;
        t9 = t8 ^ t7;
        t10 = y2 & y7;
        t11 = t10 ^ t7;
        t12 = y9 & y11;
        t13 = y14 & y17;
        t14 = t13 ^ t12;
        t15 = y8 & y10;
        t16 = t15 ^ t12;
        t17 = t4 ^ t14;
        t18 = t6 ^ t16;
        t19 = t9 ^ t14;
        t20 = t11 ^ t16;
        t21 = t17 ^ y20;
        t22 = t18 ^ y19;
        t23 = t19 ^ y21;
        t24 = t20 ^ y18;
    
        t25 = t21 ^ t22;
        t26 = t21 & t23;
        t27 = t24 ^ t26;
        t28 = t25 & t27;
        t29 = t28 ^ t22;
        t30 = t23 ^ t24;
        t31 = t22 ^ t26;
        t32 = t31 & t30;
        t33 = t32 ^ t24;
        t34 = t23 ^ t33;
        t35 = t27 ^ t33;
        t36 = t24 & t35;
        t37 = t36 ^ t34;
        t38 = t27 ^ t36;
        t39 = t29 & t38;
        t40 = t25 ^ t39;
    
        t41 = t40 ^ t37;
        t42 = t29 ^ t33;
        t43 = t29 ^ t40;
        t44 = t33 ^ t37;
        t45 = t42 ^ t41;
        z0 = t44 & y15;
        z1 = t37 & y3;
        z2 = t33 & x7;
        z3 = t43 & y16;
        z4 = t40 & y1;
        z5 = t29 & y7;
        z6 = t42 & y11;
        z7 = t45 & y17;
        z8 = t41 & y10;
        z9 = t44 & y12;
        z10 = t37 & y3;
        z11 = t33 & y4;
        z12 = t43 & y13;
        z13 = t40 & y5;
        z14 = t29 & y2;
        z15 = t42 & y9;
        z16 = t45 & y14;
        z17 = t41 & y8;
    
        // Bottom linear transformation
        t46 = z15 ^ z16;
        t47 = z10 ^ z11;
        t48 = z5 ^ z13;
        t49 = z9 ^ z10;
        t50 = z2 ^ z12;
        t51 = z2 ^ z5;
        t52 = z7 ^ z8;
        t53 = z0 ^ z3;
        t54 = z6 ^ z7;
        t55 = z16 ^ z17;
        t56 = z12 ^ t48;
        t57 = t50 ^ t53;
        t58 = z4 ^ t46;
        t59 = z3 ^ t54;
        t60 = t46 ^ t57;
        t61 = z14 ^ t57;
        t62 = t52 ^ t58;
        t63 = t49 ^ t58;
        t64 = z4 ^ t59;
        t65 = t61 ^ t62;
        t66 = z1 ^ t63;
        s0 = t59 ^ t63;
        s6 = t56 ^ !t62;
        s7 = t48 ^ !t60;
        t67 = t64 ^ t65;
        s3 = t53 ^ t66;
        s4 = t51 ^ t66;
        s5 = t47 ^ t65;
        s1 = t64 ^ !s3;
        s2 = t55 ^ !t67;
    
        q[7] = s0;
        q[6] = s1;
        q[5] = s2;
        q[4] = s3;
        q[3] = s4;
        q[2] = s5;
        q[1] = s6;
        q[0] = s7;
    }


    pub fn br_aes_ct64_ortho(q: &mut [u64; 8]) {
        macro_rules! swapn {
        ($cl:expr, $ch:expr, $s:expr, $x:expr, $y:expr) => {{
            let a = $x;
            let b = $y;
            $x = (a & $cl as u64) | ((b & $cl as u64) << $s);
            $y = ((a & $ch as u64) >> $s) | (b & $ch as u64);
        }};
    }

        macro_rules! swap2 {
        ($x:expr, $y:expr) => {
            swapn!(0x5555555555555555u128, 0xAAAAAAAAAAAAAAAAu128, 1, $x, $y);
        };
    }

        macro_rules! swap4 {
        ($x:expr, $y:expr) => {
            swapn!(0x3333333333333333u128, 0xCCCCCCCCCCCCCCCCu128, 2, $x, $y);
        };
    }

        macro_rules! swap8 {
        ($x:expr, $y:expr) => {
            swapn!(0x0F0F0F0F0F0F0F0Fu128, 0xF0F0F0F0F0F0F0F0Fu128, 4, $x, $y);
        };
    }

        swap2!(q[0], q[1]);
        swap2!(q[2], q[3]);
        swap2!(q[4], q[5]);
        swap2!(q[6], q[7]);

        swap4!(q[0], q[2]);
        swap4!(q[1], q[3]);
        swap4!(q[4], q[6]);
        swap4!(q[5], q[7]);

        swap8!(q[0], q[4]);
        swap8!(q[1], q[5]);
        swap8!(q[2], q[6]);
        swap8!(q[3], q[7]);
    }

    pub fn br_aes_ct64_interleave_in(q0: &mut u64, q1: &mut u64, w: &[u32]) {
        let mut x0 = w[0] as u64;
        let mut x1 = w[1] as u64;
        let mut x2 = w[2] as u64;
        let mut x3 = w[3] as u64;
        x0 |= x0 << 16;
        x1 |= x1 << 16;
        x2 |= x2 << 16;
        x3 |= x3 << 16;
        x0 &= 0x0000FFFF0000FFFF;
        x1 &= 0x0000FFFF0000FFFF;
        x2 &= 0x0000FFFF0000FFFF;
        x3 &= 0x0000FFFF0000FFFF;
        *q0 = x0 | (x2 << 8);
        *q1 = x1 | (x3 << 8);
    }
    
    pub fn br_aes_ct64_interleave_out(w: &mut [u32], q0: u64, q1: u64) {
        let mut x0 = q0 & 0x00FF00FF00FF00FF;
        let mut x1 = q1 & 0x00FF00FF00FF00FF;
        let mut x2 = (q0 >> 8) & 0x00FF00FF00FF00FF;
        let mut x3 = (q1 >> 8) & 0x00FF00FF00FF00FF;
        x0 |= x0 >> 8;
        x1 |= x1 >> 8;
        x2 |= x2 >> 8;
        x3 |= x3 >> 8;
        x0 &= 0x0000FFFF0000FFFF;
        x1 &= 0x0000FFFF0000FFFF;
        x2 &= 0x0000FFFF0000FFFF;
        x3 &= 0x0000FFFF0000FFFF;
        w[0] = x0 as u32 | (x0 >> 16) as u32;
        w[1] = x1 as u32 | (x1 >> 16) as u32;
        w[2] = x2 as u32 | (x2 >> 16) as u32;
        w[3] = x3 as u32 | (x3 >> 16) as u32;
    }
    
    static RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    
    pub fn sub_word(x: u32) -> u32 {
        let mut q: [u64; 8] = [0; 8];
    
        q[0] = x as u64;
        br_aes_ct64_ortho(&mut q);
        br_aes_ct64_bitslice_sbox(&mut q);
        br_aes_ct64_ortho(&mut q);
        q[0] as u32
    }

    pub fn br_aes_ct64_keysched(comp_skey: &mut [u64], key: &[u8]) {
        let mut skey: [u32; 60] = [0; 60];
        let mut tmp: u32;
        let key_len = 32;
        let nk = key_len >> 2;
        let nkf = (14 + 1) << 2;

        br_range_dec32le(&mut skey, key_len >> 2, key);
        tmp = skey[(key_len >> 2) - 1];

        let mut j = 0;
        let mut k = 0;

        for i in nk..nkf {
            if j == 0 {
                tmp = (tmp << 24) | (tmp >> 8);
                tmp = sub_word(tmp) ^ RCON[k as usize] as u32;
            } else if nk > 6 && j == 4 {
                tmp = sub_word(tmp);
            }
            tmp ^= skey[i - nk];
            skey[i] = tmp;
            if j == nk {
                j = 0;
                k += 1;
            } else {
                j += 1;
            }
        }

        let mut j = 0;

        for i in (0..nkf).step_by(4) {
            let mut temp: [u32; 4] = [0; 4];

            // Extract 4 u32 values from skey into temp
            temp.copy_from_slice(&skey[i..i + 4]);

            let mut q0 = 0;
            let mut q1 = 0;

            br_aes_ct64_interleave_in(&mut q0, &mut q1, &temp);

            br_aes_ct64_ortho(&mut [q0, q1, 0, 0, 0, 0, 0, 0]);

            for idx in 0..4 {
                let q_idx = idx * 2;
                comp_skey[j] = (q0 & 0x1111111111111111)
                    | (q1 & 0x2222222222222222)
                    | (comp_skey[j] & 0x4444444444444444)
                    | (comp_skey[j + 1] & 0x8888888888888888);
                comp_skey[j + 1] = (q0 & 0x1111111111111111)
                    | (q1 & 0x2222222222222222)
                    | (comp_skey[j] & 0x4444444444444444)
                    | (comp_skey[j + 1] & 0x8888888888888888);
                j += 2;
            }
        }
    }

    pub fn br_aes_ct64_skey_expand(skey: &mut [u64], comp_skey: &[u64]) {
        let n = (14 + 1) << 1;
        let mut u = 0;
        let mut v = 0;
    
        for _ in 0..n {
            let mut x0 = comp_skey[u];
            let mut x1 = comp_skey[u];
            let mut x2 = comp_skey[u];
            let mut x3 = comp_skey[u];
    
            x0 &= 0x1111111111111111;
            x1 &= 0x2222222222222222;
            x2 &= 0x4444444444444444;
            x3 &= 0x8888888888888888;
            x1 >>= 1;
            x2 >>= 2;
            x3 >>= 3;
            skey[v] = (x0 << 4) - x0;
            skey[v + 1] = (x1 << 4) - x1;
            skey[v + 2] = (x2 << 4) - x2;
            skey[v + 3] = (x3 << 4) - x3;
            u += 1;
            v += 4;
        }
    }
    
    pub fn add_round_key(q: &mut [u64; 8], sk: &[u64]) {
        q[0] ^= sk[0];
        q[1] ^= sk[1];
        q[2] ^= sk[2];
        q[3] ^= sk[3];
        q[4] ^= sk[4];
        q[5] ^= sk[5];
        q[6] ^= sk[6];
        q[7] ^= sk[7];
    }
    
    pub fn shift_rows(q: &mut [u64; 8]) {
        let mut tmp: [u64; 8] = [0; 8];
    
        for i in 0..8 {
            let x = q[i];
            tmp[i] = (x & 0x000000000000FFFF)
                | ((x & 0x00000000FFF00000) >> 4)
                | ((x & 0x00000000000F0000) << 12)
                | ((x & 0x0000FF0000000000) >> 8)
                | ((x & 0x000000FF00000000) << 8)
                | ((x & 0xF000000000000000) >> 12)
                | ((x & 0x0FFF000000000000) << 4);
        }
    
        q.copy_from_slice(&tmp);
    }
    
    pub fn rotr32(x: u64) -> u64 {
        (x << 32) | (x >> 32)
    }
    
    pub fn mix_columns(q: &mut [u64; 8]) {
        let mut q0 = q[0];
        let mut q1 = q[1];
        let mut q2 = q[2];
        let mut q3 = q[3];
        let mut q4 = q[4];
        let mut q5 = q[5];
        let mut q6 = q[6];
        let mut q7 = q[7];
    
        let r0 = (q0 >> 16) | (q0 << 48);
        let r1 = (q1 >> 16) | (q1 << 48);
        let r2 = (q2 >> 16) | (q2 << 48);
        let r3 = (q3 >> 16) | (q3 << 48);
        let r4 = (q4 >> 16) | (q4 << 48);
        let r5 = (q5 >> 16) | (q5 << 48);
        let r6 = (q6 >> 16) | (q6 << 48);
        let r7 = (q7 >> 16) | (q7 << 48);
    
        q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
        q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
        q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
        q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
        q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
        q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
        q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
        q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
    }
    
    pub fn inc4_be(x: &mut [u32]) {
        for xi in x.iter_mut() {
            *xi = xi.to_be() + 4;
            *xi = u32::from_be(*xi);
        }
    }

    pub fn aes_ctr4x(out: &mut [u8], ivw: &mut [u32], sk_exp: &[u64]) {
        let mut w: [u32; 16] = [0; 16];
        let mut q: [u64; 8] = [0; 8];

        w.copy_from_slice(ivw);

        for i in 0..4 {
            let mut q_temp1: u64 = 0;
            let mut q_temp2: u64 = 0;
            br_aes_ct64_interleave_in(&mut q_temp1, &mut q_temp2, &w[i * 4..]);
            q[i] = q_temp1;
            q[i + 4] = q_temp2;
        }

        br_aes_ct64_ortho(&mut q);

        add_round_key(&mut q, sk_exp);

        for i in 1..14 {
            br_aes_ct64_bitslice_sbox(&mut q);
            shift_rows(&mut q);
            mix_columns(&mut q);
            add_round_key(&mut q, &sk_exp[i * 8..]);
        }

        br_aes_ct64_bitslice_sbox(&mut q);
        shift_rows(&mut q);
        add_round_key(&mut q, &sk_exp[112..]);

        br_aes_ct64_ortho(&mut q);

        for i in 0..4 {
            let mut q_temp1 = q[i];
            let mut q_temp2 = q[i + 4];
            br_aes_ct64_interleave_out(&mut w[i * 4..], q_temp1, q_temp2);
        }

        br_range_enc32le(out, &w, 16);

        inc4_be(&mut ivw[12..]);
    }

    pub fn br_aes_ct64_ctr_init(sk_exp: &mut [u64; 120], key: &[u8]) {
        let mut skey: [u64; 30] = [0; 30];
    
        br_aes_ct64_keysched(&mut skey, key);
        br_aes_ct64_skey_expand(sk_exp, &skey);
    }
    pub fn br_aes_ct64_ctr_run(sk_exp: &mut [u64; 120], iv: &[u8], cc: u32, data: &mut [u8], mut len: usize) {
        let mut ivw: [u32; 16] = [0; 16];

        br_range_dec32le(&mut ivw, 3, iv);

        let mut ivw_copy: [u32; 16] = [0; 16]; // Create a temporary array for the copy
        ivw_copy[0..12].copy_from_slice(&ivw[0..12]);
        ivw_copy[3] = cc.to_be();
        ivw_copy[7] = (cc + 1).to_be();
        ivw_copy[11] = (cc + 2).to_be();
        ivw_copy[15] = (cc + 3).to_be();

        let mut data_ptr = 0;  

        while len > 64 {
            aes_ctr4x(&mut data[data_ptr..(data_ptr + 64)], &mut ivw_copy, sk_exp);
            data_ptr += 64;
            len -= 64;
        }
        if len > 0 {
            let mut tmp: [u8; 64] = [0; 64];
            aes_ctr4x(&mut tmp, &mut ivw_copy, sk_exp);
            for i in 0..len {
                data[data_ptr + i] = tmp[i];
            }
        }
    }


    pub fn aes256ctr_prf(out: &mut [u8], outlen: usize, key: &[u8], nonce: &[u8]) {
        let mut sk_exp: [u64; 120] = [0; 120];
    
        br_aes_ct64_ctr_init(&mut sk_exp, key);
        br_aes_ct64_ctr_run(&mut sk_exp, nonce, 0, out, outlen);
    }

    pub fn aes256ctr_init(s: &mut crate::xof_state::Aes256CtrCtx, key: &[u8], nonce: &[u8]) {
        br_aes_ct64_ctr_init(&mut s.sk_exp, key);

        br_range_dec32le(&mut s.ivw, 3, nonce);

        let mut temp_slice = [0u32; 16];
        temp_slice[0..12].copy_from_slice(&s.ivw[0..12]);
        temp_slice[3] = 0;
        temp_slice[7] = 1;
        temp_slice[11] = 2;
        temp_slice[15] = 3;

        s.ivw.copy_from_slice(&temp_slice);
    }

    pub fn aes256ctr_squeezeblocks(out: &mut [u8], nblocks: usize, s: &mut crate::xof_state::Aes256CtrCtx) {
        let mut out_ptr = 0;  

        for _ in 0..nblocks {
            aes_ctr4x(&mut out[out_ptr..(out_ptr + 64)], &mut s.ivw, &s.sk_exp);
            out_ptr += 64;
        }
    }

}