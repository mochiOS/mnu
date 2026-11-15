//! x86 TSC calibration and ordered reads; no scheduling or wall-clock policy.
use crate::arch::counter::{ClockInfo, ClockSource};
use core::arch::{asm, x86_64::__cpuid_count};
use core::sync::atomic::{AtomicBool, Ordering};

static USE_RDTSCP: AtomicBool = AtomicBool::new(false);

pub fn initialize() -> ClockInfo {
    let maximum_extended_leaf = cpuid(0x8000_0000, 0).eax;
    let rdtscp = maximum_extended_leaf >= 0x8000_0001 && cpuid(0x8000_0001, 0).edx & (1 << 27) != 0;
    let invariant_tsc =
        maximum_extended_leaf >= 0x8000_0007 && cpuid(0x8000_0007, 0).edx & (1 << 8) != 0;
    let (frequency_khz, source) = tsc_frequency();

    USE_RDTSCP.store(rdtscp, Ordering::Release);
    ClockInfo {
        invariant_tsc,
        rdtscp,
        frequency_khz,
        source,
    }
}

#[inline]
pub fn timestamp() -> u64 {
    if USE_RDTSCP.load(Ordering::Acquire) {
        read_rdtscp()
    } else {
        read_ordered_tsc()
    }
}

fn tsc_frequency() -> (u32, ClockSource) {
    #[cfg(not(mnu_arch_probe))]
    let hypervisor_frequency = crate::hypervisor_guest::tsc_frequency_khz();
    // A freestanding CPU diagnostic is not a calibrated mBoot guest.
    #[cfg(mnu_arch_probe)]
    let hypervisor_frequency = 0;
    if hypervisor_frequency != 0 {
        return (hypervisor_frequency, ClockSource::HypervisorVirtual);
    }

    let maximum_basic_leaf = cpuid(0, 0).eax;
    if maximum_basic_leaf >= 0x15 {
        let ratio = cpuid(0x15, 0);
        if ratio.eax != 0 && ratio.ebx != 0 && ratio.ecx != 0 {
            let frequency_hz =
                u64::from(ratio.ecx).saturating_mul(u64::from(ratio.ebx)) / u64::from(ratio.eax);
            if let Ok(frequency_khz) = u32::try_from(frequency_hz / 1_000) {
                return (frequency_khz, ClockSource::CpuidCrystal);
            }
        }
    }

    (0, ClockSource::Unavailable)
}

#[derive(Clone, Copy)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    let result = __cpuid_count(leaf, subleaf);
    CpuidResult {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

#[inline]
fn read_ordered_tsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(high) << 32) | u64::from(low)
}

#[inline]
fn read_rdtscp() -> u64 {
    let low: u32;
    let high: u32;
    let auxiliary: u32;
    unsafe {
        asm!(
            "rdtscp",
            "lfence",
            out("eax") low,
            out("edx") high,
            out("ecx") auxiliary,
            options(nomem, nostack, preserves_flags),
        );
    }
    let _ = auxiliary;
    (u64::from(high) << 32) | u64::from(low)
}
