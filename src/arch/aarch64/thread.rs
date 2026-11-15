//! Native initial register conversion, independent of process/Handle policy.
use super::exception::SyscallUserContext;

/// Convert caller-selected GPR values without accepting privileged controls.
/// The caller validates the creation flags, reserved words and memory rights.
pub(crate) fn initial_context(input: &mnu_abi::ThreadCreateContext) -> (SyscallUserContext, u64) {
    let mut context = SyscallUserContext::empty();
    context.instruction_pointer = input.entry;
    context.stack_pointer = input.stack_pointer;
    context.registers[0] = input.argument;
    context.registers[1..].copy_from_slice(&input.registers.x);
    // EL0t, ordinary interrupts enabled, FP/SIMD reset. TLS is installed from
    // the retained Thread object, outside this pure register image.
    (context, input.argument)
}
