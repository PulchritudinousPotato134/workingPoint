pub enum XofState {
    Aes256CtrCtx(Aes256CtrCtx),
    KeccakState(KeccakState),
}

pub trait XofAbsorb {
    fn absorb(state: &mut Self, seed: &[u8], x: u8, y: u8);
    fn new() -> Self;
}

#[derive(Clone)]
pub struct Aes256CtrCtx {
    pub(crate) sk_exp: [u64; 120],
    pub(crate) ivw: [u32; 16],
}

impl XofAbsorb for Aes256CtrCtx {
    fn absorb(state: &mut Self, mut seed: &[u8], x: u8, y: u8) {
       crate::symmetric_aes::symmetric_aes::kyber_aes256xof_absorb(state, seed, x ,y );
    }

    fn new() -> Self {
        // Initialization for Aes256CtrCtx
        Aes256CtrCtx {
            sk_exp: [0u64; 120],
            ivw: [0u32; 16],
        }
    }
}

#[derive(Clone)]
pub struct KeccakState {
    pub(crate) s: [u64; 25],
}

impl XofAbsorb for KeccakState {
    fn absorb(state: &mut Self, mut seed: &[u8], x: u8, y: u8) {
       crate::symmetric_shake::symmetric_shake::kyber_shake128_absorb(state, seed, x ,y );
    }

    fn new() -> Self {
        // Initialization for KeccakState
        KeccakState {
            s:[0u64; 25],
        }
    }
}

