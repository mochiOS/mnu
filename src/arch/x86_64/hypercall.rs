use super::super::hypercall::Transport;
use core::arch::asm;

pub const fn supported(transport: Transport) -> bool {
    matches!(transport, Transport::IntelVmx | Transport::AmdSvm)
}

/// Read the active hypervisor's CPUID calibration leaf, not host wall time.
pub fn virtual_tsc_frequency_khz() -> Option<u32> {
    let value: u64;
    // SAFETY: CPUID is available on x86_64; preserve LLVM's reserved RBX.
    unsafe {
        asm!(
            "mov {saved:r}, rbx",
            "cpuid",
            "xchg {saved:r}, rbx",
            saved = inout(reg) 0u64 => value,
            inout("eax") 0x4000_0001u32 => _,
            out("ecx") _, out("edx") _,
            options(nomem, nostack),
        );
    }
    u32::try_from(value).ok().filter(|value| *value != 0)
}

/// # Safety
/// Run at CPL0 under the selected active VMX/SVM hypercall transport.
pub unsafe fn invoke(transport: Transport, number: u64, arguments: [u64; 3]) -> Option<u64> {
    let result;
    // SAFETY: The caller guarantees the active transport and privilege level.
    unsafe {
        match transport {
            Transport::IntelVmx => asm!(
                "vmcall", inlateout("rax") number => result,
                inlateout("rdi") arguments[0] => _,
                inlateout("rsi") arguments[1] => _,
                inlateout("rdx") arguments[2] => _,
                clobber_abi("sysv64"), options(nostack),
            ),
            Transport::AmdSvm => asm!(
                "vmmcall", inlateout("rax") number => result,
                inlateout("rdi") arguments[0] => _,
                inlateout("rsi") arguments[1] => _,
                inlateout("rdx") arguments[2] => _,
                clobber_abi("sysv64"), options(nostack),
            ),
            Transport::ArmEl2 => return None,
        }
    }
    Some(result)
}
