#![no_std]
#![no_main]

use core::mem::size_of;
use core::panic::PanicInfo;

mod domain_hypercall;

use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, PciDeviceInfo, ShutdownReason, DOMAIN_CAPABILITY_DEVICE_QUERY,
    DOMAIN_FEATURE_DEVICE_QUERY, DOMAIN_FEATURE_READY, DOMAIN_FEATURE_WAIT, DOMAIN_ROLE_HARDWARE,
    HYPERCALL_SUCCESS,
};

static START_MESSAGE: &[u8] = b"Hardware Domain bootstrap entered\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    let required_features =
        DOMAIN_FEATURE_DEVICE_QUERY | DOMAIN_FEATURE_READY | DOMAIN_FEATURE_WAIT;
    if boot_info.validate().is_err()
        || boot_info.domain_role != DOMAIN_ROLE_HARDWARE
        || boot_info.feature_flags & required_features != required_features
        || boot_info.capabilities & DOMAIN_CAPABILITY_DEVICE_QUERY == 0
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        )
    }
    console_write(boot_info, START_MESSAGE);

    let info_address = boot_info.grant_window_start;
    let result = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::DeviceQuery,
            0,
            info_address,
            size_of::<PciDeviceInfo>() as u64,
        )
    };
    let info = unsafe { &*(info_address as *const PciDeviceInfo) };
    if result != HYPERCALL_SUCCESS || !info.validate() {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }

    if unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::Ready,
            0,
            0,
            0,
        )
    } != HYPERCALL_SUCCESS
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }

    loop {
        let _ = unsafe { invoke(boot_info.hypervisor_backend, HypercallNumber::Wait, 0, 0, 0) };
    }
}

fn console_write(boot_info: &DomainBootInfo, message: &[u8]) {
    let _ = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            message.as_ptr() as u64,
            message.len() as u64,
            0,
        )
    };
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
