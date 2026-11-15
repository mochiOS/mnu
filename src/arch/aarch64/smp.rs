//! Initial native CPU admission. Secondary-vCPU startup requires a native EL1
//! bootstrap and an EL2 CPU-start transport; neither is advertised as ready.
use crate::BootInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidBootInfo,
    UnsupportedTopology,
}

/// A single assigned vCPU can boot without inventing x86 CR3/APIC handoff
/// fields. Reject a larger topology until its native startup is implemented.
pub fn admit_boot_cpu(info: &BootInfo) -> Result<(), Error> {
    info.validate().map_err(|_| Error::InvalidBootInfo)?;
    if info.cpu_enabled != 1
        || info.cpu_id_count != 1
        || info.cpu_hardware_ids[0] != info.bsp_hardware_id
    {
        return Err(Error::UnsupportedTopology);
    }
    Ok(())
}

#[cfg(not(mnu_arch_probe))]
pub fn start_secondary_cpus() {
    let admission = crate::smp::boot_info()
        .ok_or(Error::InvalidBootInfo)
        .and_then(admit_boot_cpu);
    if let Err(error) = admission {
        crate::error!("Native CPU startup unavailable: {:?}", error);
        crate::arch::halt();
    }
    // This records the actually running CPU, never every firmware entry.
    crate::mem::tlb_shootdown::mark_current_cpu_online();
}

#[cfg(not(mnu_arch_probe))]
pub(crate) fn send_fixed_ipi(cpu: u32, vector: u8) -> bool {
    if cpu as usize != crate::percpu::current_cpu_id() {
        // Remote notification cannot be claimed before native CPU startup and
        // assigned SGI delivery exist. VM revocation propagates this failure.
        return false;
    }
    // The callers avoid self-IPIs. A local request can be fulfilled directly
    // without fabricating a GIC Distributor or sending an arbitrary device IRQ.
    match vector {
        crate::mem::tlb_shootdown::VECTOR => {
            crate::mem::tlb_shootdown::service_pending();
            true
        }
        crate::task::scheduler::WAKE_VECTOR => true, // This CPU is executing.
        _ => false,
    }
}
