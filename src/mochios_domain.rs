#![no_std]
#![no_main]

use core::panic::PanicInfo;
mod domain_hypercall;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_FEATURE_GRANT_TABLE, DOMAIN_FEATURE_READY, DOMAIN_FEATURE_SHARED_RING,
    DOMAIN_ROLE_SYSTEM, HYPERCALL_INVALID_ARGUMENT, HYPERCALL_SUCCESS, HYPERCALL_UNSUPPORTED,
    HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX,
};

static START_MESSAGE: &[u8] = b"mochiOS System Domain entered\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        invalid_boot_info(HYPERVISOR_BACKEND_AMD_SVM)
    };
    if boot_info.validate().is_err()
        || boot_info.domain_role != DOMAIN_ROLE_SYSTEM
        || boot_info.feature_flags
            & (DOMAIN_FEATURE_READY
                | DOMAIN_FEATURE_EVENT_CHANNEL
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING)
            != DOMAIN_FEATURE_READY
                | DOMAIN_FEATURE_EVENT_CHANNEL
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING
    {
        invalid_boot_info(boot_info.hypervisor_backend)
    }

    let _ = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            START_MESSAGE.as_ptr() as u64,
            START_MESSAGE.len() as u64,
            0,
        )
    };
    let ready = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::Ready,
            0,
            0,
            0,
        )
    };
    if ready != HYPERCALL_SUCCESS {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }

    loop {
        let result = unsafe {
            invoke(
                boot_info.hypervisor_backend,
                HypercallNumber::EventWait,
                0,
                0,
                0,
            )
        };
        if matches!(result, HYPERCALL_UNSUPPORTED | HYPERCALL_INVALID_ARGUMENT) {
            shutdown(
                boot_info.hypervisor_backend,
                ShutdownReason::InitializationFailed,
            )
        }
    }
}

fn invalid_boot_info(backend: u32) -> ! {
    if matches!(
        backend,
        HYPERVISOR_BACKEND_INTEL_VMX | HYPERVISOR_BACKEND_AMD_SVM
    ) {
        shutdown(backend, ShutdownReason::InvalidBootInfo)
    }
    halt_forever()
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
