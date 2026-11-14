//! Fresh EL0 entry. Validating an image, installing its address space and
//! applying process policy remain the kernel caller's responsibilities.

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
