//! Privileged CPU transport only. Call numbers, Domain ownership and resource
//! policy belong to the caller and the hypervisor, not this instruction bridge.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    IntelVmx,
    AmdSvm,
    ArmEl2,
}

pub use super::selected::hypercall::{invoke, supported, virtual_tsc_frequency_khz};
