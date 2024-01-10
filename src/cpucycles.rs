

pub mod cpucycles
{
    extern "C" {
        pub fn cpucycles() -> uint64_t;
    }

    pub fn cpucycles_overhead() -> uint64_t {
        let mut t0: uint64_t;
        let mut t1: uint64_t;
        let mut overhead = MAX;

        for _ in 0..100000 {
            unsafe {
                t0 = cpucycles();
                asm!("" :::: "volatile");
                t1 = cpucycles();
            }
            if t1.wrapping_sub(t0) < overhead {
                overhead = t1.wrapping_sub(t0);
            }
        }

        overhead
    }

    pub fn main() {
        let overhead = cpucycles_overhead();
        println!("CPU cycles overhead: {}", overhead);
    }
}
