//! Fresh EL0 entry. Validating an image, installing its address space and
//! applying process policy remain the kernel caller's responsibilities.

use super::exception::UserContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeError {
    InvalidContext,
    InvalidTls,
    InvalidKernelStack,
}

/// Restore an explicit EL0 continuation with a syscall result in x0.
/// Invalid register images return without changing hardware state.
///
/// # Safety
/// Run at EL1h with FP/SIMD enabled and SVE/SME disabled. The caller retains
/// `context` in mapped kernel memory through entry, pins and installs the
/// selected process's address space, and validates executable/writable EL0
/// code/stack mappings. `kernel_stack_top` must name a separately owned,
/// writable kernel stack, retained and mapped for subsequent exceptions.
/// This abandons the calling kernel continuation; none of its locks may remain
/// held. TLS is a user address, not a grant or a CPU-local state pointer.
pub unsafe fn resume_user(
    context: &UserContext,
    result: u64,
    thread_local_base: u64,
    kernel_stack_top: u64,
) -> Result<core::convert::Infallible, ResumeError> {
    if !context.valid() {
        return Err(ResumeError::InvalidContext);
    }
    if thread_local_base > 0x0000_7fff_ffff_ffff {
        return Err(ResumeError::InvalidTls);
    }
    if kernel_stack_top == 0 || kernel_stack_top & 15 != 0 {
        return Err(ResumeError::InvalidKernelStack);
    }
    // SAFETY: Register validation completed before any state is changed. The
    // caller supplies the retained address space and trusted exception stack.
    unsafe { resume_validated(context, thread_local_base, result, kernel_stack_top) }
}

#[unsafe(naked)]
unsafe extern "C" fn resume_validated(
    context: *const UserContext,
    thread_local_base: u64,
    result: u64,
    kernel_stack_top: u64,
) -> ! {
    core::arch::naked_asm!(
        "msr daifset, #15",
        "mov x30, x0",
        "msr tpidr_el0, x1",
        "msr tpidrro_el0, xzr",
        "ldr x9, [x30, #248]",
        "msr sp_el0, x9",
        "ldr x9, [x30, #256]",
        "msr elr_el1, x9",
        "ldr x9, [x30, #264]",
        "msr spsr_el1, x9",
        "ldr x9, [x30, #272]",
        "msr fpcr, x9",
        "ldr x9, [x30, #280]",
        "msr fpsr, x9",
        // A retained kernel pointer is used until the final load. Discard the
        // abandoned call frames before EL0 can cause another exception.
        "mov sp, x3",
        "mov x0, x2",
        "ldp q0, q1, [x30, #288]",
        "ldp q2, q3, [x30, #320]",
        "ldp q4, q5, [x30, #352]",
        "ldp q6, q7, [x30, #384]",
        "ldp q8, q9, [x30, #416]",
        "ldp q10, q11, [x30, #448]",
        "ldp q12, q13, [x30, #480]",
        "ldp q14, q15, [x30, #512]",
        "ldp q16, q17, [x30, #544]",
        "ldp q18, q19, [x30, #576]",
        "ldp q20, q21, [x30, #608]",
        "ldp q22, q23, [x30, #640]",
        "ldp q24, q25, [x30, #672]",
        "ldp q26, q27, [x30, #704]",
        "ldp q28, q29, [x30, #736]",
        "ldp q30, q31, [x30, #768]",
        "ldp x1, x2, [x30, #8]",
        "ldp x3, x4, [x30, #24]",
        "ldp x5, x6, [x30, #40]",
        "ldp x7, x8, [x30, #56]",
        "ldp x9, x10, [x30, #72]",
        "ldp x11, x12, [x30, #88]",
        "ldp x13, x14, [x30, #104]",
        "ldp x15, x16, [x30, #120]",
        "ldp x17, x18, [x30, #136]",
        "ldp x19, x20, [x30, #152]",
        "ldp x21, x22, [x30, #168]",
        "ldp x23, x24, [x30, #184]",
        "ldp x25, x26, [x30, #200]",
        "ldp x27, x28, [x30, #216]",
        "ldr x29, [x30, #232]",
        "ldr x30, [x30, #240]",
        "eret",
    );
}

/// Enter AArch64 EL0t with only x0 and the explicit TLS base initialized.
/// Other integer registers, FP/SIMD and TPIDRRO_EL0 are cleared so kernel
/// register contents cannot become the new thread's initial register state.
///
/// # Safety
/// Must run at EL1h with FP/SIMD enabled and SVE/SME disabled. The caller must
/// validate and install executable EL0 mappings for `entry`, an aligned writable
/// EL0 stack, and an allowed TLS base. A separate valid kernel stack and the
/// exception vectors/handler must remain mapped for traps. Register clearing
/// does not provide memory or Domain isolation; those require MMU/mBoot setup.
#[unsafe(naked)]
pub unsafe extern "C" fn enter_user(
    entry: u64,
    stack_pointer: u64,
    argument: u64,
    thread_local_base: u64,
) -> ! {
    core::arch::naked_asm!(
        "msr daifset, #15",
        "msr sp_el0, x1",
        "msr elr_el1, x0",
        "msr spsr_el1, xzr", // EL0t, AArch64, IRQs unmasked
        "msr tpidr_el0, x3",
        "msr tpidrro_el0, xzr",
        "msr fpcr, xzr",
        "msr fpsr, xzr",
        "mov x0, x2",
        "mov x1, xzr",
        "mov x2, xzr",
        "mov x3, xzr",
        "mov x4, xzr",
        "mov x5, xzr",
        "mov x6, xzr",
        "mov x7, xzr",
        "mov x8, xzr",
        "mov x9, xzr",
        "mov x10, xzr",
        "mov x11, xzr",
        "mov x12, xzr",
        "mov x13, xzr",
        "mov x14, xzr",
        "mov x15, xzr",
        "mov x16, xzr",
        "mov x17, xzr",
        "mov x18, xzr",
        "mov x19, xzr",
        "mov x20, xzr",
        "mov x21, xzr",
        "mov x22, xzr",
        "mov x23, xzr",
        "mov x24, xzr",
        "mov x25, xzr",
        "mov x26, xzr",
        "mov x27, xzr",
        "mov x28, xzr",
        "mov x29, xzr",
        "mov x30, xzr",
        "movi v0.16b, #0",
        "movi v1.16b, #0",
        "movi v2.16b, #0",
        "movi v3.16b, #0",
        "movi v4.16b, #0",
        "movi v5.16b, #0",
        "movi v6.16b, #0",
        "movi v7.16b, #0",
        "movi v8.16b, #0",
        "movi v9.16b, #0",
        "movi v10.16b, #0",
        "movi v11.16b, #0",
        "movi v12.16b, #0",
        "movi v13.16b, #0",
        "movi v14.16b, #0",
        "movi v15.16b, #0",
        "movi v16.16b, #0",
        "movi v17.16b, #0",
        "movi v18.16b, #0",
        "movi v19.16b, #0",
        "movi v20.16b, #0",
        "movi v21.16b, #0",
        "movi v22.16b, #0",
        "movi v23.16b, #0",
        "movi v24.16b, #0",
        "movi v25.16b, #0",
        "movi v26.16b, #0",
        "movi v27.16b, #0",
        "movi v28.16b, #0",
        "movi v29.16b, #0",
        "movi v30.16b, #0",
        "movi v31.16b, #0",
        "eret",
    );
}
