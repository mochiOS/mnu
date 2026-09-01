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

    let required = core::mem::size_of::<mnu_abi::performance::KernelPerformanceSnapshot>();
    if output_len < required as u64 {
        return EINVAL;
    }

    #[cfg(feature = "performance-instrumentation")]
    {
        let snapshot = crate::performance::snapshot();
        // The fixed-layout snapshot remains alive until copy_to_user returns.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&snapshot as *const mnu_abi::performance::KernelPerformanceSnapshot).cast::<u8>(),
                required,
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
