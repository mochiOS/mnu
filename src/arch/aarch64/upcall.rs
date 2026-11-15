//! Native ARM snapshot and AAPCS64 callback conventions. No token, process,
//! capability or user-memory authority is created by a register conversion.
use super::exception::UserUpcallContext;
use super::fp::State;

pub(crate) fn extension(snapshot: &mnu_abi::ThreadUpcallSnapshot) -> [u8; 512] {
    snapshot.fp_state
}
pub(crate) fn stack_pointer(context: &UserUpcallContext) -> u64 {
    context.stack_pointer
}
pub(crate) fn instruction_pointer(context: &UserUpcallContext) -> u64 {
    context.instruction_pointer
}
pub(crate) fn result(context: &UserUpcallContext) -> u64 {
    context.registers[0]
}
pub(crate) fn valid_return(context: &UserUpcallContext) -> bool {
    context.valid()
}
pub(crate) fn valid_callback(entry: u64, stack: u64) -> bool {
    let mut context = UserUpcallContext::empty();
    context.instruction_pointer = entry;
    context.stack_pointer = stack;
    context.valid()
}

pub(crate) fn callback_stack(end: u64, _exception: bool) -> u64 {
    end & !15
}
pub(crate) fn return_slot(_stack: u64) -> Option<u64> {
    None
} // LR, not a stack return address.
pub(crate) fn exception_argument_slot(_stack: u64) -> Option<u64> {
    None
} // Seventh argument is x6.

pub(crate) fn callback(
    context: &mut UserUpcallContext,
    entry: u64,
    stack: u64,
    arguments: [u64; 7],
) {
    context.instruction_pointer = entry;
    context.stack_pointer = stack;
    context.pstate = 0; // EL0t, ordinary interrupts unmasked.
    context.registers[..7].copy_from_slice(&arguments);
    context.registers[30] = 0; // An unexpected callback RET faults in user space.
}

pub(crate) fn decode(snapshot: &mnu_abi::ThreadUpcallSnapshot) -> Option<UserUpcallContext> {
    let mut context = UserUpcallContext::empty();
    context.instruction_pointer = snapshot.instruction;
    context.stack_pointer = snapshot.stack_pointer;
    context.pstate = snapshot.pstate;
    context.registers[0] = snapshot.argument;
    context.registers[1..].copy_from_slice(&snapshot.registers.x);
    context.fpcr = snapshot.fpcr;
    context.fpsr = snapshot.fpsr;
    let state = State::initial().with_user_context(&context, snapshot.fp_state)?;
    Some(state.restore_context(context))
}

pub(crate) fn snapshot(
    context: UserUpcallContext,
    fp_state: [u8; 512],
) -> mnu_abi::ThreadUpcallSnapshot {
    mnu_abi::ThreadUpcallSnapshot {
        instruction: context.instruction_pointer,
        stack_pointer: context.stack_pointer,
        pstate: context.pstate,
        argument: context.registers[0],
        registers: mnu_abi::ThreadInitialRegisters {
            x: core::array::from_fn(|index| context.registers[index + 1]),
        },
        fp_state,
        fpcr: context.fpcr,
        fpsr: context.fpsr,
    }
}
