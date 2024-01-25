pub mod speed_print
{
    //THIS IS TRANSLATED BUT NOT USED CURRENTLY
    use std::cmp::Ordering;

    pub fn cmp_uint64(a: &u64, b: &u64) -> Ordering {
        a.cmp(b)
    }

    pub fn median(l: &mut [u64], llen: usize) -> u64 {
        l.sort_by(cmp_uint64);

        if llen % 2 == 1 {
            l[llen / 2]
        } else {
            (l[llen / 2 - 1] + l[llen / 2]) / 2
        }
    }

    pub fn average(t: &[u64]) -> u64 {
        let acc = t.iter().sum::<u64>();
        acc / t.len() as u64
    }

    pub fn print_results(s: &str, t: &mut [u64]) {
        let tlen = t.len();
        let mut overhead = u64::MAX;

        if tlen < 2 {
            eprintln!("ERROR: Need at least two cycle counts!");
            return;
        }

        if overhead == u64::MAX {
            
            overhead = 0;
        }

        let tlen = tlen - 1;
        for i in 0..tlen {
            t[i] = t[i + 1] - t[i] - overhead;
        }

        println!("{}", s);
        println!("median: {} cycles/ticks", median(t, tlen));
        println!("average: {} cycles/ticks", average(&t[..tlen]));
        println!();
    }
}