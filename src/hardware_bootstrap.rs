#![no_std]
#![no_main]

use core::mem::size_of;
use core::panic::PanicInfo;

mod domain_hypercall;

use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, PciDeviceInfo, ShutdownReason, DOMAIN_CAPABILITY_DEVICE_CLAIM,
    DOMAIN_CAPABILITY_DEVICE_QUERY, DOMAIN_FEATURE_DEVICE_OWNERSHIP, DOMAIN_FEATURE_DEVICE_QUERY,
    DOMAIN_FEATURE_READY, DOMAIN_FEATURE_WAIT, DOMAIN_ROLE_HARDWARE, HYPERCALL_INVALID_ARGUMENT,
    HYPERCALL_SUCCESS, PCI_DEVICE_FLAG_CLAIMABLE, PCI_DEVICE_STATE_CLAIMED_DISABLED,
    PCI_DEVICE_STATE_QUARANTINED,
};

static START_MESSAGE: &[u8] = b"Hardware Domain bootstrap entered\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    let required_features = DOMAIN_FEATURE_DEVICE_QUERY
        | DOMAIN_FEATURE_DEVICE_OWNERSHIP
        | DOMAIN_FEATURE_READY
        | DOMAIN_FEATURE_WAIT;
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
    for index in 0..256_u64 {
        let result = query_device(boot_info, index, info_address);
        if result == HYPERCALL_INVALID_ARGUMENT {
            break;
        }
        let info = unsafe { &*(info_address as *const PciDeviceInfo) };
        if result != HYPERCALL_SUCCESS || !info.validate() {
            initialization_failed(boot_info)
        }
        if info.flags & PCI_DEVICE_FLAG_CLAIMABLE != 0 {
            if boot_info.capabilities & DOMAIN_CAPABILITY_DEVICE_CLAIM == 0
                || unsafe {
                    invoke(
                        boot_info.hypervisor_backend,
                        HypercallNumber::DeviceClaim,
                        u64::from(info.requester),
                        0,
                        0,
                    )
                } != HYPERCALL_SUCCESS
            {
                initialization_failed(boot_info)
            }
            if query_device(boot_info, index, info_address) != HYPERCALL_SUCCESS {
                initialization_failed(boot_info)
            }
            let claimed = unsafe { &*(info_address as *const PciDeviceInfo) };
            if claimed.state != PCI_DEVICE_STATE_CLAIMED_DISABLED
                || claimed.owner_domain != boot_info.domain_id
            {
                initialization_failed(boot_info)
            }
            if unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::DeviceRelease,
                    u64::from(claimed.requester),
                    0,
                    0,
                )
            } != HYPERCALL_SUCCESS
            {
                initialization_failed(boot_info)
            }
            if query_device(boot_info, index, info_address) != HYPERCALL_SUCCESS
                || unsafe { &*(info_address as *const PciDeviceInfo) }.state
                    != PCI_DEVICE_STATE_QUARANTINED
            {
                initialization_failed(boot_info)
            }
        }
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

fn query_device(boot_info: &DomainBootInfo, index: u64, destination: u64) -> u64 {
    unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::DeviceQuery,
            index,
            destination,
            size_of::<PciDeviceInfo>() as u64,
        )
    }
}

fn initialization_failed(boot_info: &DomainBootInfo) -> ! {
    shutdown(
        boot_info.hypervisor_backend,
        ShutdownReason::InitializationFailed,
    )
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
