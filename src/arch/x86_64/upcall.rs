//! x86 register/snapshot and C callback conventions. Thread ownership,
//! tokens, usercopy and executable memory checks remain in syscall/task.
use super::exception::UserUpcallContext;
pub(crate) fn valid_callback(entry: u64, stack: u64) -> bool {
    entry != 0 && entry >> 47 == 0 && stack >> 47 == 0 && stack & 15 == 8
}

pub(crate) fn extension(snapshot: &mnu_abi::ThreadUpcallSnapshot) -> [u8; 512] {
    snapshot.fx_state
}
pub(crate) fn stack_pointer(context: &UserUpcallContext) -> u64 {
    context.user_rsp
}
pub(crate) fn instruction_pointer(context: &UserUpcallContext) -> u64 {
    context.user_rip
}
pub(crate) fn result(context: &UserUpcallContext) -> u64 {
    context.rax
}

pub(crate) fn callback_stack(end: u64, exception: bool) -> u64 {
    (end & !15).saturating_sub(if exception { 24 } else { 8 })
}
pub(crate) fn return_slot(stack: u64) -> Option<u64> {
    Some(stack)
}
pub(crate) fn exception_argument_slot(stack: u64) -> Option<u64> {
    Some(stack + 8)
}

/// Assign the SysV integer arguments; the seventh is written to its owned
/// stack slot by the faultable usercopy layer, outside this CPU mechanism.
pub(crate) fn callback(
    context: &mut UserUpcallContext,
    entry: u64,
    stack: u64,
    arguments: [u64; 7],
) {
    context.user_rip = entry;
    context.user_rsp = stack;
    context.user_rflags &= !((1 << 10) | (1 << 8) | (1 << 16));
    context.rdi = arguments[0];
    context.rsi = arguments[1];
    context.rdx = arguments[2];
    context.rcx = arguments[3];
    context.r8 = arguments[4];
    context.r9 = arguments[5];
}

pub(crate) fn decode(snapshot: &mnu_abi::ThreadUpcallSnapshot) -> Option<UserUpcallContext> {
    // Only user-modifiable arithmetic/debug flags are accepted. In particular
    // IOPL, NT, VM and virtual-interrupt flags must never reach IRET/FXRSTOR.
    const REQUIRED: u64 = (1 << 1) | (1 << 9);
    const ALLOWED: u64 = REQUIRED
        | (1 << 0)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 10)
        | (1 << 11)
        | (1 << 16)
        | (1 << 18)
        | (1 << 21);
    if snapshot.rflags & REQUIRED != REQUIRED || snapshot.rflags & !ALLOWED != 0 {
        return None;
    }
    let registers = &snapshot.registers;
    let context = UserUpcallContext {
        user_rip: snapshot.instruction,
        user_rsp: snapshot.stack_pointer,
        user_rflags: snapshot.rflags,
        rdi: snapshot.argument,
        rax: registers.rax,
        rbx: registers.rbx,
        rcx: registers.rcx,
        rdx: registers.rdx,
        rsi: registers.rsi,
        rbp: registers.rbp,
        r8: registers.r8,
        r9: registers.r9,
        r10: registers.r10,
        r11: registers.r11,
        r12: registers.r12,
        r13: registers.r13,
        r14: registers.r14,
        r15: registers.r15,
    };
    valid_return(&context).then_some(context)
}

pub(crate) fn snapshot(
    context: UserUpcallContext,
    fx_state: [u8; 512],
) -> mnu_abi::ThreadUpcallSnapshot {
    mnu_abi::ThreadUpcallSnapshot {
        instruction: context.user_rip,
        stack_pointer: context.user_rsp,
        rflags: context.user_rflags,
        argument: context.rdi,
        registers: mnu_abi::ThreadInitialRegisters {
            rax: context.rax,
            rbx: context.rbx,
            rcx: context.rcx,
            rdx: context.rdx,
            rsi: context.rsi,
            rbp: context.rbp,
            r8: context.r8,
            r9: context.r9,
            r10: context.r10,
            r11: context.r11,
            r12: context.r12,
            r13: context.r13,
            r14: context.r14,
            r15: context.r15,
        },
        fx_state,
    }
}

pub(crate) fn valid_return(context: &UserUpcallContext) -> bool {
    context.user_rip != 0 && context.user_rip >> 47 == 0 && context.user_rsp >> 47 == 0
}
