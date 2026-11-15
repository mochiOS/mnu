/// Remaining x86-64 general registers at initial entry. RDI is `argument` and
/// RSP is `stack_pointer`. Segment selectors and privileged flags are not
/// caller-controlled; new threads start with interrupts enabled and IOPL zero.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadInitialRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

/// Read-only x86-64 context captured before entering a native upcall.
/// RDI is `argument`; the remaining GPRs use the native thread register layout.
/// `fx_state` is the 512-byte FXSAVE64 image (x87/SSE, not AVX/XSAVE).
/// Editing the copy alone does not change the kernel's return context. It may
/// be supplied to ThreadUpcallReturnContext for an active delivery, or to
/// ThreadContextRestore for an independent self continuation. Both validate
/// user CPU state atomically and leave TLS and execution authority unchanged.
#[repr(C, align(16))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadUpcallSnapshot {
    pub instruction: u64,
    pub stack_pointer: u64,
    pub rflags: u64,
    pub argument: u64,
    pub registers: ThreadInitialRegisters,
    pub fx_state: [u8; 512],
}

/// Register word order used by the explicitly tagged creation wire format.
impl ThreadInitialRegisters {
    pub const WORDS: usize = 14;
    pub const fn from_words(r: [u64; Self::WORDS]) -> Self {
        Self {
            rax: r[0],
            rbx: r[1],
            rcx: r[2],
            rdx: r[3],
            rsi: r[4],
            rbp: r[5],
            r8: r[6],
            r9: r[7],
            r10: r[8],
            r11: r[9],
            r12: r[10],
            r13: r[11],
            r14: r[12],
            r15: r[13],
        }
    }
    pub const fn words(self) -> [u64; Self::WORDS] {
        [
            self.rax, self.rbx, self.rcx, self.rdx, self.rsi, self.rbp, self.r8, self.r9, self.r10,
            self.r11, self.r12, self.r13, self.r14, self.r15,
        ]
    }
}
pub const CREATION_CONTEXT_KIND: u32 = 1;
const _: () = assert!(core::mem::size_of::<ThreadUpcallSnapshot>() == 656);
const _: () = assert!(core::mem::offset_of!(ThreadUpcallSnapshot, fx_state) == 144);
