//! ARM architected virtual counter. EL2 supplies its offset and EL1 access;
//! wall-clock origin and timer interrupt routing remain separate mechanisms.
use crate::arch::counter::{ClockInfo, ClockSource};
use core::arch::asm;

pub fn frequency_hz() -> u64 {
    let value;
    // SAFETY: CNTFRQ_EL0 is readable at EL1 under the boot counter contract.
    unsafe {
        asm!("mrs {}, cntfrq_el0", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

pub fn initialize() -> ClockInfo {
    let frequency_khz = u32::try_from(frequency_hz() / 1000)
        .ok()
        .filter(|value| *value != 0);
    ClockInfo {
        // These legacy metadata flags describe x86 instructions only.
        invariant_tsc: false,
        rdtscp: false,
        frequency_khz: frequency_khz.unwrap_or(0),
        source: if frequency_khz.is_some() {
            ClockSource::ArchitectedCounter
        } else {
            ClockSource::Unavailable
        },
    }
}

#[inline]
pub fn timestamp() -> u64 {
    let value;
    // SAFETY: Read-only EL1 counter access. ISB orders the sample with respect
    // to instruction execution; no wall-clock value or fallback is invented.
    unsafe {
        asm!("isb", "mrs {}, cntvct_el0", out(reg) value, options(nostack, preserves_flags));
    }
    value
}
