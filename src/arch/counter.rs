//! Serialized CPU counters. Frequency provenance is explicit; no device timer
//! or userspace clock policy belongs in this interface.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClockSource {
    Unavailable = 0,
    HypervisorVirtual = 1,
    CpuidCrystal = 2,
    ArchitectedCounter = 3,
}

impl ClockSource {
    pub(crate) fn from_raw(value: u8) -> Self {
        match value {
            1 => Self::HypervisorVirtual,
            2 => Self::CpuidCrystal,
            3 => Self::ArchitectedCounter,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockInfo {
    /// x86 instruction properties. Both are false for an ARM counter.
    pub invariant_tsc: bool,
    pub rdtscp: bool,
    /// Calibrated raw counter rate in kHz; zero means calibration unavailable.
    /// This is not a wall-clock origin or the scheduling interrupt frequency.
    pub frequency_khz: u32,
    pub source: ClockSource,
}

#[cfg(target_arch = "aarch64")]
pub use super::selected::counter::frequency_hz;
pub use super::selected::counter::{initialize, timestamp};
