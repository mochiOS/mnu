//! Native initial register conversion, independent of process/Handle policy.
use super::exception::SyscallUserContext;

/// Convert validated creation metadata; privilege flags remain kernel-owned.
pub(crate) fn initial_context(input: &mnu_abi::ThreadCreateContext) -> (SyscallUserContext, u64) {
    let registers = input.registers;
    (
        SyscallUserContext {
            rip: input.entry,
            rsp: input.stack_pointer,
            rflags: 0x202,
            rdi: input.argument,
            rsi: registers.rsi,
            rdx: registers.rdx,
            r8: registers.r8,
            r9: registers.r9,
            r10: registers.r10,
            rbp: registers.rbp,
            rbx: registers.rbx,
            r12: registers.r12,
            r13: registers.r13,
            r14: registers.r14,
            r15: registers.r15,
            rcx: registers.rcx,
            r11: registers.r11,
        },
        registers.rax,
    )
}
