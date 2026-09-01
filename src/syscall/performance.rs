use crate::capability::Capability;

#[cfg(not(feature = "performance-instrumentation"))]
use super::ENOTSUP;
#[cfg(feature = "performance-instrumentation")]
use super::SUCCESS;
use super::{EACCES, EINVAL};

pub fn snapshot(output: u64, output_len: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[Capability::DeveloperProfile]) {
        return EACCES;
    }

    let minimum = mnu_abi::performance::PERFORMANCE_SNAPSHOT_V1_SIZE;
    if output_len < minimum as u64 {
        return EINVAL;
    }

    #[cfg(feature = "performance-instrumentation")]
    {
        let available = core::mem::size_of::<mnu_abi::performance::KernelPerformanceSnapshot>();
        let snapshot = crate::performance::snapshot();
        let copy_len = usize::try_from(output_len)
            .unwrap_or(usize::MAX)
            .min(available);
        // The fixed-layout snapshot remains alive until copy_to_user returns.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&snapshot as *const mnu_abi::performance::KernelPerformanceSnapshot).cast::<u8>(),
                copy_len,
            )
        };
        return match crate::syscall::copy_to_user(output, bytes) {
            Ok(()) => SUCCESS,
            Err(error) => error,
        };
    }

    #[cfg(not(feature = "performance-instrumentation"))]
    {
        let _ = output;
        ENOTSUP
    }
}
