#![no_std]
#![no_main]

use core::panic::PanicInfo;
mod domain_hypercall;
mod domain_interrupt;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_FEATURE_EVENT_IRQ, DOMAIN_FEATURE_GRANT_QUERY, DOMAIN_FEATURE_GRANT_TABLE,
    DOMAIN_FEATURE_READY, DOMAIN_FEATURE_SHARED_RING, DOMAIN_FEATURE_VIRTUAL_APIC,
    DOMAIN_ROLE_SYSTEM, GRANT_FLAG_WRITABLE, GRANT_REF_INVALID, HYPERCALL_INVALID_ARGUMENT,
    HYPERCALL_SUCCESS, HYPERCALL_UNSUPPORTED, HYPERVISOR_BACKEND_AMD_SVM,
    HYPERVISOR_BACKEND_INTEL_VMX, MDRIVER_CONTROL_IRQ_PORT, MDRIVER_CONTROL_PORT,
    MDRIVER_CONTROL_REQUEST_KIND, MDRIVER_CONTROL_RESPONSE_KIND, MDRIVER_CONTROL_RING_GENERATION,
    MDRIVER_CONTROL_RING_PORT, MDRIVER_DOMAIN_ID,
};
use mnu_abi::shared_ring::{
    initialize, pop_response, push_request, SharedRingMessage, SharedRingPage,
};

static START_MESSAGE: &[u8] = b"mochiOS System Domain entered\n";
static MDRIVER_EVENT_MESSAGE: &[u8] = b"mDriver control Event Channel verified\n";
static MDRIVER_RING_MESSAGE: &[u8] = b"mDriver control Shared Ring verified\n";
const CONTROL_IRQ_YIELD_LIMIT: usize = 1024;
const CONTROL_REQUEST_ID: u64 = 1;

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
                | DOMAIN_FEATURE_EVENT_IRQ
                | DOMAIN_FEATURE_GRANT_QUERY
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING
                | DOMAIN_FEATURE_VIRTUAL_APIC)
            != DOMAIN_FEATURE_READY
                | DOMAIN_FEATURE_EVENT_CHANNEL
                | DOMAIN_FEATURE_EVENT_IRQ
                | DOMAIN_FEATURE_GRANT_QUERY
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING
                | DOMAIN_FEATURE_VIRTUAL_APIC
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

    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventSend,
            u64::from(MDRIVER_CONTROL_PORT),
            0,
            0,
        )
    });
    require_port(boot_info, MDRIVER_CONTROL_PORT, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventWait,
            0,
            0,
            0,
        )
    });

    unsafe { domain_interrupt::install() };
    if unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventIrqEnable,
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

    let mut acknowledged_interrupts = domain_interrupt::event_count();
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventSend,
            u64::from(MDRIVER_CONTROL_IRQ_PORT),
            0,
            0,
        )
    });
    for _ in 0..CONTROL_IRQ_YIELD_LIMIT {
        if domain_interrupt::event_count() != acknowledged_interrupts {
            break;
        }
        require_success(boot_info, unsafe {
            invoke(
                boot_info.hypervisor_backend,
                HypercallNumber::Yield,
                0,
                0,
                0,
            )
        });
    }
    if domain_interrupt::event_count() == acknowledged_interrupts {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    require_port(boot_info, MDRIVER_CONTROL_IRQ_PORT, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventWait,
            0,
            0,
            0,
        )
    });
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::IrqEoi,
            0,
            0,
            0,
        )
    });
    acknowledged_interrupts = domain_interrupt::event_count();
    console_write(boot_info, MDRIVER_EVENT_MESSAGE);

    verify_control_ring(boot_info);

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
        let delivered_interrupts = domain_interrupt::event_count();
        if delivered_interrupts != acknowledged_interrupts {
            if unsafe {
                invoke(
                    boot_info.hypervisor_backend,
                    HypercallNumber::IrqEoi,
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
            acknowledged_interrupts = delivered_interrupts;
        }
    }
}

fn verify_control_ring(boot_info: &DomainBootInfo) {
    let ring = boot_info.grant_window_start as *mut SharedRingPage;
    unsafe { initialize(ring, MDRIVER_CONTROL_RING_GENERATION) };
    let request = SharedRingMessage::new(
        MDRIVER_CONTROL_REQUEST_KIND,
        0,
        CONTROL_REQUEST_ID,
        b"probe",
    )
    .unwrap_or_else(|_| initialization_failed(boot_info));
    unsafe { push_request(ring, request) }.unwrap_or_else(|_| initialization_failed(boot_info));
    let reference = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantCreate,
            boot_info.grant_window_start,
            u64::from(MDRIVER_DOMAIN_ID),
            GRANT_FLAG_WRITABLE,
        )
    };
    if reference == GRANT_REF_INVALID
        || matches!(
            reference,
            HYPERCALL_UNSUPPORTED | HYPERCALL_INVALID_ARGUMENT
        )
    {
        initialization_failed(boot_info)
    }
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventSend,
            u64::from(MDRIVER_CONTROL_RING_PORT),
            0,
            0,
        )
    });
    require_port(boot_info, MDRIVER_CONTROL_RING_PORT, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventWait,
            0,
            0,
            0,
        )
    });
    let response =
        unsafe { pop_response(ring) }.unwrap_or_else(|_| initialization_failed(boot_info));
    if response.kind != MDRIVER_CONTROL_RESPONSE_KIND
        || response.flags != 0
        || response.request_id != CONTROL_REQUEST_ID
        || response.data() != Ok(b"ready".as_slice())
    {
        initialization_failed(boot_info)
    }
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantRevoke,
            reference,
            0,
            0,
        )
    });
    console_write(boot_info, MDRIVER_RING_MESSAGE);
}

fn initialization_failed(boot_info: &DomainBootInfo) -> ! {
    shutdown(
        boot_info.hypervisor_backend,
        ShutdownReason::InitializationFailed,
    )
}

fn require_success(boot_info: &DomainBootInfo, result: u64) {
    if result != HYPERCALL_SUCCESS {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
}

fn require_port(boot_info: &DomainBootInfo, expected: u32, result: u64) {
    if result != u64::from(expected) {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
}

fn console_write(boot_info: &DomainBootInfo, message: &[u8]) {
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::ConsoleWrite,
            message.as_ptr() as u64,
            message.len() as u64,
            0,
        )
    });
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
