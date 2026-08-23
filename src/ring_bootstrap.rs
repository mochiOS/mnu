#![no_std]
#![no_main]

use core::panic::PanicInfo;
mod domain_hypercall;
mod domain_interrupt;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_FEATURE_EVENT_IRQ, DOMAIN_FEATURE_GRANT_TABLE, DOMAIN_FEATURE_SHARED_RING,
    DOMAIN_FEATURE_VIRTUAL_APIC, DOMAIN_ROLE_HARDWARE, DOMAIN_ROLE_SYSTEM, EVENT_CHANNEL_VECTOR,
    GRANT_FLAG_WRITABLE, HYPERCALL_SUCCESS,
};
use mnu_abi::shared_ring::{
    initialize, pop_request, pop_response, push_request, push_response, validate,
    SharedRingMessage, SharedRingPage,
};

const TEST_PORT: u64 = 1;
const FIRST_GRANT_REF: u64 = 0x101;
const RING_GENERATION: u64 = 7;
const REQUEST_KIND: u16 = 1;
const RESPONSE_KIND: u16 = 2;
const REQUEST_ID: u64 = 42;
static START_MESSAGE: &[u8] = b"Shared Ring bootstrap entered\n";
static REQUEST_MESSAGE: &[u8] = b"Shared Ring request handled\n";
static RESPONSE_MESSAGE: &[u8] = b"Shared Ring response verified\n";
static IRQ_MESSAGE: &[u8] = b"Event Channel IRQ received\n";

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.domain_entry")]
pub unsafe extern "sysv64" fn domain_entry(boot_info_ptr: *const DomainBootInfo) -> ! {
    let Some(boot_info) = (unsafe { boot_info_ptr.as_ref() }) else {
        halt_forever()
    };
    let required = DOMAIN_FEATURE_EVENT_CHANNEL
        | DOMAIN_FEATURE_EVENT_IRQ
        | DOMAIN_FEATURE_GRANT_TABLE
        | DOMAIN_FEATURE_SHARED_RING
        | DOMAIN_FEATURE_VIRTUAL_APIC;
    if boot_info.validate().is_err() || boot_info.feature_flags & required != required {
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
    unsafe { domain_interrupt::install() };
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventIrqEnable,
            0,
            0,
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
    let ring = boot_info.grant_window_start as *mut SharedRingPage;
    unsafe { initialize(ring, RING_GENERATION) };
    let request =
        SharedRingMessage::new(REQUEST_KIND, 0, REQUEST_ID, b"request").unwrap_or_else(|_| {
            shutdown(
                boot_info.hypervisor_backend,
                ShutdownReason::InitializationFailed,
            )
        });
    if unsafe { push_request(ring, request) }.is_err() {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
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

    let response = unsafe { pop_response(ring) }.unwrap_or_else(|_| {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    });
    if response.kind != RESPONSE_KIND
        || response.request_id != REQUEST_ID
        || response.data() != Ok(b"response".as_slice())
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    console_write(boot_info.hypervisor_backend, RESPONSE_MESSAGE);
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
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqSetTpr,
            u64::from(EVENT_CHANNEL_VECTOR),
            0,
            0,
        )
    });
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqMask,
            u64::from(EVENT_CHANNEL_VECTOR),
            1,
            0,
        )
    });
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqMask,
            u64::from(EVENT_CHANNEL_VECTOR),
            0,
            0,
        )
    });
    if domain_interrupt::event_count() != 0 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqSetTpr,
            0,
            0,
            0,
        )
    });
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::Yield,
            0,
            0,
            0,
        )
    });
    wait_event(boot_info.hypervisor_backend);
    if domain_interrupt::event_count() == 0 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqEoi,
            0,
            0,
            0,
        )
    });
    console_write(boot_info.hypervisor_backend, IRQ_MESSAGE);
    require_success(boot_info.hypervisor_backend, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantMap,
            FIRST_GRANT_REF,
            boot_info.grant_window_start,
            0,
        )
    });
    let ring = boot_info.grant_window_start as *mut SharedRingPage;
    if unsafe { validate(ring) } != Ok(RING_GENERATION) {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    let request = unsafe { pop_request(ring) }.unwrap_or_else(|_| {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    });
    if request.kind != REQUEST_KIND
        || request.request_id != REQUEST_ID
        || request.data() != Ok(b"request".as_slice())
    {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    let response = SharedRingMessage::new(RESPONSE_KIND, 0, REQUEST_ID, b"response")
        .unwrap_or_else(|_| {
            shutdown(
                boot_info.hypervisor_backend,
                ShutdownReason::InitializationFailed,
            )
        });
    if unsafe { push_response(ring, response) }.is_err() {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    console_write(boot_info.hypervisor_backend, REQUEST_MESSAGE);
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

fn console_write(backend: u32, message: &[u8]) {
    require_success(backend, unsafe {
        invoke(
            backend,
            HypercallNumber::ConsoleWrite,
            message.as_ptr() as u64,
            message.len() as u64,
            0,
        )
    });
}

fn wait_event(backend: u32) {
    if unsafe { invoke(backend, HypercallNumber::EventWait, 0, 0, 0) } != TEST_PORT {
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
