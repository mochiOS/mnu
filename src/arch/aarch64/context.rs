//! EL1 kernel continuation for the base AAPCS64 / FP-SIMD register set.
//! Exception entry must retain caller-saved registers before scheduling. This
//! mechanism does not replace that frame, switch address spaces or install TLS.
//! SVE/SME must remain disabled until their extended state has its own save path.

#[cfg(any(target_feature = "sve", target_feature = "sme"))]
compile_error!("AArch64 kernel contexts do not yet preserve SVE/SME state");

#[derive(Debug, Clone, Copy)]
#[repr(C, align(16))]
pub struct Context {
    // x19..x29 (including FP), followed by LR. Assembly offsets below are part
    // of this internal kernel frame, not a user-controlled register ABI.
    callee_saved: [u64; 12],
    sp: u64,
    pc: u64,
    nzcv: u64,
    daif: u64,
    simd: [u128; 32],
    fpcr: u64,
    fpsr: u64,
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

impl Context {
    pub const fn new() -> Self {
        Self {
            callee_saved: [0; 12],
            sp: 0,
            pc: 0,
            nzcv: 0,
            daif: 0x3c0,
            simd: [0; 32],
            fpcr: 0,
            fpsr: 0,
        }
    }

    /// Prepare an EL1 entry with a terminal frame and a 16-byte aligned SP.
    /// Debug, SError and FIQ start masked; only the requested IRQ state varies.
    ///
    /// # Safety
    /// `stack_top` must be 16-byte aligned with at least 16 writable bytes below
    /// it, exclusively owned by this context. Both code addresses must be valid
    /// kernel entry points. FP/SIMD access must be enabled before switching.
    pub unsafe fn for_kernel_entry(
        entry: u64,
        stack_top: u64,
        return_address: u64,
        interrupts_enabled: bool,
    ) -> Self {
        let mut context = Self::new();
        context.sp = stack_top - 16;
        context.pc = entry;
        context.callee_saved[10] = context.sp; // x29: terminal frame
        context.callee_saved[11] = return_address; // x30: entry's return address
        context.daif = if interrupts_enabled { 0x340 } else { 0x3c0 };
        unsafe {
            (context.sp as *mut u64).write(0);
            ((context.sp + 8) as *mut u64).write(return_address);
        }
        context
    }

    pub fn stack_pointer(&self) -> u64 {
        self.sp
    }

    pub fn instruction_pointer(&self) -> u64 {
        self.pc
    }
}

const _: () = {
    assert!(core::mem::offset_of!(Context, callee_saved) == 0);
    assert!(core::mem::offset_of!(Context, sp) == 96);
    assert!(core::mem::offset_of!(Context, pc) == 104);
    assert!(core::mem::offset_of!(Context, nzcv) == 112);
    assert!(core::mem::offset_of!(Context, daif) == 120);
    assert!(core::mem::offset_of!(Context, simd) == 128);
    assert!(core::mem::offset_of!(Context, fpcr) == 640);
    assert!(core::mem::offset_of!(Context, fpsr) == 648);
    assert!(core::mem::size_of::<Context>() == 656);
    assert!(core::mem::align_of::<Context>() == 16);
};

/// Save a kernel continuation and resume another one on this CPU.
/// All 128 bits of every FP/SIMD register are saved, beyond the base AAPCS64
/// callee-save requirement, so a preempted exception frame can retain FP state.
///
/// # Safety
/// Both contexts and their stacks must be valid, aligned, exclusively owned
/// kernel memory mapped in the active address space. FP/SIMD must be enabled.
/// `outgoing_marker` must point to this CPU's live aligned AtomicU64 handoff
/// marker, published before selecting the incoming thread. The caller retains
/// ownership until its release-clear, which occurs only after saving the old
/// context and abandoning the old stack. Contexts must not contain user input.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn switch_context(
    old_context: *mut Context,
    new_context: *const Context,
    outgoing_marker: *mut u64,
) {
    core::arch::naked_asm!(
        "mrs x9, daif",
        "msr daifset, #2",
        "stp x19, x20, [x0, #0]",
        "stp x21, x22, [x0, #16]",
        "stp x23, x24, [x0, #32]",
        "stp x25, x26, [x0, #48]",
        "stp x27, x28, [x0, #64]",
        "stp x29, x30, [x0, #80]",
        "mov x10, sp",
        "stp x10, x30, [x0, #96]",
        "mrs x10, nzcv",
        "stp x10, x9, [x0, #112]",
        "stp q0, q1, [x0, #128]",
        "stp q2, q3, [x0, #160]",
        "stp q4, q5, [x0, #192]",
        "stp q6, q7, [x0, #224]",
        "stp q8, q9, [x0, #256]",
        "stp q10, q11, [x0, #288]",
        "stp q12, q13, [x0, #320]",
        "stp q14, q15, [x0, #352]",
        "stp q16, q17, [x0, #384]",
        "stp q18, q19, [x0, #416]",
        "stp q20, q21, [x0, #448]",
        "stp q22, q23, [x0, #480]",
        "stp q24, q25, [x0, #512]",
        "stp q26, q27, [x0, #544]",
        "stp q28, q29, [x0, #576]",
        "stp q30, q31, [x0, #608]",
        "mrs x10, fpcr",
        "str x10, [x0, #640]",
        "mrs x10, fpsr",
        "str x10, [x0, #648]",
        "ldp q0, q1, [x1, #128]",
        "ldp q2, q3, [x1, #160]",
        "ldp q4, q5, [x1, #192]",
        "ldp q6, q7, [x1, #224]",
        "ldp q8, q9, [x1, #256]",
        "ldp q10, q11, [x1, #288]",
        "ldp q12, q13, [x1, #320]",
        "ldp q14, q15, [x1, #352]",
        "ldp q16, q17, [x1, #384]",
        "ldp q18, q19, [x1, #416]",
        "ldp q20, q21, [x1, #448]",
        "ldp q22, q23, [x1, #480]",
        "ldp q24, q25, [x1, #512]",
        "ldp q26, q27, [x1, #544]",
        "ldp q28, q29, [x1, #576]",
        "ldp q30, q31, [x1, #608]",
        "ldr x10, [x1, #640]",
        "msr fpcr, x10",
        "ldr x10, [x1, #648]",
        "msr fpsr, x10",
        "ldp x19, x20, [x1, #0]",
        "ldp x21, x22, [x1, #16]",
        "ldp x23, x24, [x1, #32]",
        "ldp x25, x26, [x1, #48]",
        "ldp x27, x28, [x1, #64]",
        "ldp x29, x30, [x1, #80]",
        "ldp x11, x16, [x1, #96]",
        "ldp x9, x10, [x1, #112]",
        "mov sp, x11",
        // No accesses to the old context or stack may follow this release.
        "stlr xzr, [x2]",
        "msr nzcv, x9",
        "msr daif, x10",
        "br x16",
    );
}
