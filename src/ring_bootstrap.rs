#![no_std]
#![no_main]

use core::arch::asm;
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
static X2APIC_MESSAGE: &[u8] = b"x2APIC MSR interface verified\n";
static MSR_FAULT_MESSAGE: &[u8] = b"Rejected MSR delivered #GP\n";
static APIC_TIMER_MESSAGE: &[u8] = b"Local APIC timer IRQ received\n";
static SELF_IPI_MESSAGE: &[u8] = b"x2APIC self IPI received\n";

const IA32_APIC_BASE: u32 = 0x1b;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const X2APIC_TPR: u32 = 0x808;
const X2APIC_EOI: u32 = 0x80b;
const X2APIC_ICR: u32 = 0x830;
const X2APIC_LVT_TIMER: u32 = 0x832;
const X2APIC_INITIAL_COUNT: u32 = 0x838;
const X2APIC_CURRENT_COUNT: u32 = 0x839;
const X2APIC_DIVIDE_CONFIGURATION: u32 = 0x83e;
const X2APIC_SELF_IPI: u32 = 0x83f;
const APIC_TIMER_VECTOR: u8 = 0x50;
const SELF_IPI_VECTOR: u8 = 0x51;
const ICR_SELF: u64 = 1 << 18;

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
    if boot_info.domain_role == DOMAIN_ROLE_HARDWARE {
        unsafe { domain_interrupt::install_general_protection_test_handler() };
        unsafe { domain_interrupt::install_apic_test_handlers(APIC_TIMER_VECTOR, SELF_IPI_VECTOR) };
        configure_x2apic(boot_info);
        verify_rejected_msr(boot_info);
        verify_self_ipi(boot_info);
        verify_apic_timer(boot_info);
    }
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
    if unsafe { read_msr(X2APIC_TPR) } != u64::from(EVENT_CHANNEL_VECTOR) {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    console_write(boot_info.hypervisor_backend, X2APIC_MESSAGE);
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
    unsafe { write_msr(X2APIC_TPR, 0) };
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
    unsafe { write_msr(X2APIC_EOI, 0) };
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

fn configure_x2apic(boot_info: &DomainBootInfo) {
    let apic_base = unsafe { read_msr(IA32_APIC_BASE) };
    unsafe { write_msr(IA32_APIC_BASE, apic_base | APIC_BASE_X2APIC) };
    unsafe { write_msr(X2APIC_TPR, u64::from(EVENT_CHANNEL_VECTOR)) };
    if unsafe { read_msr(X2APIC_TPR) } != u64::from(EVENT_CHANNEL_VECTOR) {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
}

fn verify_rejected_msr(boot_info: &DomainBootInfo) {
    let count = domain_interrupt::general_protection_count();
    let _ = unsafe { read_msr(0x801) };
    unsafe { write_msr(0x801, 0) };
    if domain_interrupt::general_protection_count() != count + 2 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    console_write(boot_info.hypervisor_backend, MSR_FAULT_MESSAGE);
}

fn verify_self_ipi(boot_info: &DomainBootInfo) {
    let count = domain_interrupt::self_ipi_count();
    unsafe { write_msr(X2APIC_SELF_IPI, u64::from(SELF_IPI_VECTOR)) };
    if domain_interrupt::self_ipi_count() != count + 1 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    unsafe { write_msr(X2APIC_EOI, 0) };
    unsafe { write_msr(X2APIC_ICR, ICR_SELF | u64::from(SELF_IPI_VECTOR)) };
    if domain_interrupt::self_ipi_count() != count + 2 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    unsafe { write_msr(X2APIC_EOI, 0) };
    console_write(boot_info.hypervisor_backend, SELF_IPI_MESSAGE);
}

fn verify_apic_timer(boot_info: &DomainBootInfo) {
    let count = domain_interrupt::apic_timer_count();
    unsafe { write_msr(X2APIC_DIVIDE_CONFIGURATION, 0xb) };
    unsafe { write_msr(X2APIC_LVT_TIMER, u64::from(APIC_TIMER_VECTOR)) };
    unsafe { write_msr(X2APIC_INITIAL_COUNT, 1_000) };
    if unsafe { read_msr(X2APIC_CURRENT_COUNT) } > 1_000 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    for _ in 0..64 {
        if domain_interrupt::apic_timer_count() == count + 1 {
            break;
        }
        let _ = unsafe { read_msr(X2APIC_CURRENT_COUNT) };
    }
    if domain_interrupt::apic_timer_count() != count + 1 {
        shutdown(
            boot_info.hypervisor_backend,
            ShutdownReason::InitializationFailed,
        )
    }
    unsafe { write_msr(X2APIC_EOI, 0) };
    console_write(boot_info.hypervisor_backend, APIC_TIMER_MESSAGE);
}

unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            lateout("eax") low,
            lateout("edx") high,
            options(nostack)
        )
    };
    u64::from(low) | (u64::from(high) << 32)
}

unsafe fn write_msr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nostack)
        )
    };
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
