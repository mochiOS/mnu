/// x1..x30 at native entry. x0 is `argument`, SP is `stack_pointer`.
/// Privileged state is never supplied by a creator. The kernel starts EL0t,
/// enables ordinary interrupts, and clears FP/SIMD unless restoring a snapshot.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadInitialRegisters {
    pub x: [u64; 30],
}

impl ThreadInitialRegisters {
    pub const WORDS: usize = 30;
    pub const fn from_words(x: [u64; Self::WORDS]) -> Self {
        Self { x }
    }
    pub const fn words(self) -> [u64; Self::WORDS] {
        self.x
    }
}

/// Read-only base AArch64 EL0 context. Only NZCV may be selected in `pstate`
/// on restore; privilege, interrupt masks, TLS and execution authority remain
/// kernel-controlled. Q0..Q31 use little-endian 128-bit lane order.
/// SVE/SME are not enabled by this ABI.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadUpcallSnapshot {
    pub instruction: u64,
    pub stack_pointer: u64,
    pub pstate: u64,
    pub argument: u64,
    pub registers: ThreadInitialRegisters,
    pub fp_state: [u8; 512],
    pub fpcr: u64,
    pub fpsr: u64,
}

pub const CREATION_CONTEXT_KIND: u32 = 2;
const _: () = {
    assert!(core::mem::size_of::<super::ThreadCreateContext>() == 304);
    assert!(core::mem::offset_of!(super::ThreadCreateContext, registers) == 64);
    assert!(core::mem::size_of::<ThreadUpcallSnapshot>() == 800);
    assert!(core::mem::offset_of!(ThreadUpcallSnapshot, fp_state) == 272);
    assert!(core::mem::offset_of!(ThreadUpcallSnapshot, fpcr) == 784);
};
