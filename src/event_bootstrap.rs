#![no_std]
#![no_main]

use core::panic::PanicInfo;
mod domain_hypercall;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_ROLE_HARDWARE, DOMAIN_ROLE_SYSTEM, HYPERCALL_SUCCESS,
};

const TEST_PORT: u64 = 1;
static START_MESSAGE: &[u8] = b"Event Channel bootstrap entered\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    if boot_info.validate().is_err() || boot_info.feature_flags & DOMAIN_FEATURE_EVENT_CHANNEL == 0
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        )
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

    match boot_info.domain_role {
        DOMAIN_ROLE_SYSTEM => {
            require_success(boot_info.hypervisor_backend, unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::EventSend,
                    TEST_PORT,
                    0,
                    0,
                )
            });
            require_port(boot_info.hypervisor_backend, unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::EventWait,
                    0,
                    0,
                    0,
                )
            });
        }
        DOMAIN_ROLE_HARDWARE => {
            require_port(boot_info.hypervisor_backend, unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::EventWait,
                    0,
                    0,
                    0,
                )
            });
            require_success(boot_info.hypervisor_backend, unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::EventSend,
                    TEST_PORT,
                    0,
                    0,
                )
            });
        }
        _ => shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InvalidBootInfo,
        ),
    }
    shutdown(boot_info.hypervisor_backend, ShutdownReason::Completed)
}

fn require_success(backend: u32, result: u64) {
    if result != HYPERCALL_SUCCESS {
        shutdown(backend, ShutdownReason::InitializationFailed)
    }
}

fn require_port(backend: u32, port: u64) {
    if port != TEST_PORT {
        shutdown(backend, ShutdownReason::InitializationFailed)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    halt_forever()
}
