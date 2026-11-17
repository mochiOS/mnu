use crate::arch::hypercall::{self, Transport};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_ARM_EL2,
    HYPERVISOR_BACKEND_INTEL_VMX,
};

static BACKEND: AtomicU32 = AtomicU32::new(0);
static DOMAIN_ID: AtomicU32 = AtomicU32::new(0);
static FEATURE_FLAGS: AtomicU64 = AtomicU64::new(0);
static GRANT_WINDOW_START: AtomicU64 = AtomicU64::new(0);
static GRANT_WINDOW_SIZE: AtomicU64 = AtomicU64::new(0);

#[path = "hypervisor_buffer.rs"]
mod buffer;

/// Translate every page of a retained kernel buffer. An EL1 virtual pointer
/// must never be interpreted by EL2 as a guest physical address.
pub(crate) fn buffer_address(address: u64, length: usize) -> Option<u64> {
    buffer::contiguous_address(address, length, |virtual_address| {
        crate::mem::paging::translate_addr(crate::arch::memory::VirtAddr::new(virtual_address))
            .map(|physical| physical.as_u64())
    })
}

pub fn configure(info: &DomainBootInfo) -> bool {
    let backend = info.hypervisor_backend;
    if info.validate().is_err() || transport(backend).is_none() {
        return false;
    }
    DOMAIN_ID.store(info.domain_id, Ordering::Release);
    FEATURE_FLAGS.store(info.feature_flags, Ordering::Release);
    GRANT_WINDOW_START.store(info.grant_window_start, Ordering::Release);
    GRANT_WINDOW_SIZE.store(info.grant_window_size, Ordering::Release);
    BACKEND.store(backend, Ordering::Release);
    true
}

pub fn is_active() -> bool {
    BACKEND.load(Ordering::Acquire) != 0
}

pub fn domain_id() -> u32 {
    DOMAIN_ID.load(Ordering::Acquire)
}

pub fn feature_flags() -> u64 {
    FEATURE_FLAGS.load(Ordering::Acquire)
}

/// Optional platform time, independent of RTC hardware and userspace policy.
pub(crate) fn realtime_seconds() -> Option<u64> {
    use mnu_abi::hypervisor::{DOMAIN_FEATURE_REALTIME, HYPERCALL_INVALID_ARGUMENT};
    if !is_active() || feature_flags() & DOMAIN_FEATURE_REALTIME == 0 {
        return None;
    }
    let seconds = invoke(HypercallNumber::FirmwareRealtimeSeconds, 0, 0, 0);
    (seconds < HYPERCALL_INVALID_ARGUMENT).then_some(seconds)
}

pub fn grant_window() -> Option<(u64, u64)> {
    let start = GRANT_WINDOW_START.load(Ordering::Acquire);
    let size = GRANT_WINDOW_SIZE.load(Ordering::Acquire);
    (start != 0 && size != 0).then_some((start, size))
}

/// Returns the virtual TSC frequency advertised by the hypervisor, in kHz.
pub fn tsc_frequency_khz() -> u32 {
    if !is_active() {
        return 0;
    }
    hypercall::virtual_tsc_frequency_khz().unwrap_or(0)
}

pub fn invoke(number: HypercallNumber, arg0: u64, arg1: u64, arg2: u64) -> u64 {
    let Some(transport) = transport(BACKEND.load(Ordering::Acquire)) else {
        return u64::MAX;
    };
    // SAFETY: configure admits only validated native Domain boot metadata.
    unsafe { hypercall::invoke(transport, number as u64, [arg0, arg1, arg2]).unwrap_or(u64::MAX) }
}

fn transport(backend: u32) -> Option<Transport> {
    let transport = match backend {
        HYPERVISOR_BACKEND_INTEL_VMX => Transport::IntelVmx,
        HYPERVISOR_BACKEND_AMD_SVM => Transport::AmdSvm,
        HYPERVISOR_BACKEND_ARM_EL2 => Transport::ArmEl2,
        _ => return None,
    };
    hypercall::supported(transport).then_some(transport)
}
