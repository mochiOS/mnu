#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
mod domain_hypercall;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_FEATURE_GRANT_TABLE, DOMAIN_ROLE_HARDWARE, DOMAIN_ROLE_SYSTEM, GRANT_FLAG_WRITABLE,
    HYPERCALL_SUCCESS,
};

const TEST_PORT: u64 = 1;
const FIRST_GRANT_REF: u64 = 0x101;
const REQUEST_VALUE: u64 = 0x4d4f_4348_494f_5301;
const RESPONSE_VALUE: u64 = 0x4d4f_4348_494f_5302;
static START_MESSAGE: &[u8] = b"Grant and Event Channel bootstrap entered\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    if boot_info.validate().is_err()
        || boot_info.feature_flags & (DOMAIN_FEATURE_EVENT_CHANNEL | DOMAIN_FEATURE_GRANT_TABLE)
            != DOMAIN_FEATURE_EVENT_CHANNEL | DOMAIN_FEATURE_GRANT_TABLE
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        )
    }

    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            START_MESSAGE.as_ptr() as u64,
            START_MESSAGE.len() as u64,
            0,
        )
    });

    match boot_info.domain_role {
        DOMAIN_ROLE_SYSTEM => system_endpoint(boot_info),
        DOMAIN_ROLE_HARDWARE => hardware_endpoint(boot_info),
        _ => shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        ),
    }
    shutdown(boot_info.hypervisor_backend, ShutdownReason::Completed)
}

fn system_endpoint(boot_info: &DomainBootInfo) {
    let page = boot_info.grant_window_start as *mut u64;
    unsafe { write_volatile(page, REQUEST_VALUE) };
    let reference = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantCreate,
            boot_info.grant_window_start,
            2,
            GRANT_FLAG_WRITABLE,
        )
    };
    if reference != FIRST_GRANT_REF {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    send_event(boot_info.hypervisor_backend);
    wait_event(boot_info.hypervisor_backend);
    if unsafe { read_volatile(page) } != RESPONSE_VALUE {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantRevoke,
            reference,
            0,
            0,
        )
    });
}

fn hardware_endpoint(boot_info: &DomainBootInfo) {
    wait_event(boot_info.hypervisor_backend);
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantMap,
            FIRST_GRANT_REF,
            boot_info.grant_window_start,
            0,
        )
    });
    let page = boot_info.grant_window_start as *mut u64;
    if unsafe { read_volatile(page) } != REQUEST_VALUE {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    unsafe { write_volatile(page, RESPONSE_VALUE) };
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantUnmap,
            FIRST_GRANT_REF,
            0,
            0,
        )
    });
    send_event(boot_info.hypervisor_backend);
}

fn send_event(backend: u32) {
    require_success(backend, unsafe {
        invoke(backend, HypercallNumber::EventSend, TEST_PORT, 0, 0)
    });
}

fn wait_event(backend: u32) {
    let port = unsafe { invoke(backend, HypercallNumber::EventWait, 0, 0, 0) };
    if port != TEST_PORT {
        shutdown(backend, ShutdownReason::InitializationFailed)
    }
}

fn require_success(backend: u32, result: u64) {
    if result != HYPERCALL_SUCCESS {
        shutdown(backend, ShutdownReason::InitializationFailed)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
