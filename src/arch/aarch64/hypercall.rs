use super::super::hypercall::Transport;

pub const fn supported(transport: Transport) -> bool {
    matches!(transport, Transport::ArmEl2)
}

/// ARM uses its architected counter, never a CPUID virtual TSC hint.
pub fn virtual_tsc_frequency_khz() -> Option<u32> {
    None
}

/// x0 is the call number/result, x1..x3 are arguments; the native C caller
/// register set may be clobbered. EL2 must retain all callee-owned state.
///
/// # Safety
/// Run at EL1 under a hypervisor implementing this HVC #0 transport.
pub unsafe fn invoke(transport: Transport, number: u64, arguments: [u64; 3]) -> Option<u64> {
    if !supported(transport) {
        return None;
    }
    let result;
    // SAFETY: The caller guarantees the active EL2 transport and EL1 context.
    unsafe {
        core::arch::asm!(
            "hvc #0",
            inlateout("x0") number => result,
            inlateout("x1") arguments[0] => _,
            inlateout("x2") arguments[1] => _,
            inlateout("x3") arguments[2] => _,
            clobber_abi("C"),
            options(nostack),
        );
    }
    Some(result)
}
