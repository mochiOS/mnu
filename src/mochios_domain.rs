#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
mod domain_hypercall;
mod domain_interrupt;
use domain_hypercall::{halt_forever, invoke, shutdown};
use mnu_abi::hypervisor::{
    DomainBootInfo, HypercallNumber, ShutdownReason, DOMAIN_FEATURE_EVENT_CHANNEL,
    DOMAIN_FEATURE_EVENT_IRQ, DOMAIN_FEATURE_EVENT_POLL, DOMAIN_FEATURE_GRANT_QUERY,
    DOMAIN_FEATURE_GRANT_TABLE, DOMAIN_FEATURE_READY, DOMAIN_FEATURE_SHARED_RING,
    DOMAIN_FEATURE_VIRTUAL_APIC, DOMAIN_ROLE_SYSTEM, GRANT_FLAG_WRITABLE, GRANT_REF_INVALID,
    HYPERCALL_INVALID_ARGUMENT, HYPERCALL_SUCCESS, HYPERCALL_UNSUPPORTED,
    HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX, MDRIVER_BLOCK_DATA_PAGE,
    MDRIVER_CONTROL_IRQ_PORT, MDRIVER_CONTROL_PORT, MDRIVER_CONTROL_REQUEST_KIND,
    MDRIVER_CONTROL_RESPONSE_KIND, MDRIVER_CONTROL_RING_GENERATION, MDRIVER_CONTROL_RING_PORT,
    MDRIVER_DOMAIN_ID,
};
use mnu_abi::mdriver_control::{
    MdriverControlRequest, MdriverControlResponse, MDRIVER_BLOCK_MAX_TRANSFER,
    MDRIVER_BLOCK_SECTOR_SIZE, MDRIVER_CONTROL_BLOCK_FLUSH, MDRIVER_CONTROL_BLOCK_READ,
    MDRIVER_CONTROL_BLOCK_WRITE, MDRIVER_CONTROL_CAPABILITIES, MDRIVER_CONTROL_CLOSE_DEVICE,
    MDRIVER_CONTROL_DESCRIBE, MDRIVER_CONTROL_ENUMERATE, MDRIVER_CONTROL_NEGOTIATE,
    MDRIVER_CONTROL_OPEN_DEVICE, MDRIVER_CONTROL_PING, MDRIVER_CONTROL_START_SESSION,
    MDRIVER_CONTROL_STATUS_END, MDRIVER_CONTROL_STATUS_OK, MDRIVER_CONTROL_STATUS_OUT_OF_RANGE,
    MDRIVER_CONTROL_STATUS_UNSUPPORTED_OPERATION, MDRIVER_CONTROL_VERSION,
    MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH, MDRIVER_DEVICE_FEATURE_BLOCK_READ,
    MDRIVER_DEVICE_FEATURE_BLOCK_WRITE, MDRIVER_DEVICE_FEATURE_DMA_ISOLATED,
    MDRIVER_DEVICE_FEATURE_EPHEMERAL, MDRIVER_DEVICE_FEATURE_INTERRUPT_ACTIVE,
    MDRIVER_DEVICE_FEATURE_PHYSICAL, MDRIVER_DEVICE_KIND_BLOCK, MDRIVER_DEVICE_KIND_SOUND,
    MDRIVER_DEVICE_STATE_ONLINE,
};
use mnu_abi::shared_ring::{
    initialize, pop_response, push_request, SharedRingMessage, SharedRingPage,
};

static START_MESSAGE: &[u8] = b"mochiOS System Domain entered\n";
static MDRIVER_EVENT_MESSAGE: &[u8] = b"mDriver control Event Channel verified\n";
static MDRIVER_PROTOCOL_MESSAGE: &[u8] = b"mDriver device control protocol ready\n";
static MDRIVER_BLOCK_MESSAGE: &[u8] = b"mDriver block data path ready\n";
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
                | DOMAIN_FEATURE_EVENT_POLL
                | DOMAIN_FEATURE_GRANT_QUERY
                | DOMAIN_FEATURE_GRANT_TABLE
                | DOMAIN_FEATURE_SHARED_RING
                | DOMAIN_FEATURE_VIRTUAL_APIC)
            != DOMAIN_FEATURE_READY
                | DOMAIN_FEATURE_EVENT_CHANNEL
                | DOMAIN_FEATURE_EVENT_IRQ
                | DOMAIN_FEATURE_EVENT_POLL
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

    start_control_protocol(boot_info);

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

fn start_control_protocol(boot_info: &DomainBootInfo) {
    let ring = boot_info.grant_window_start as *mut SharedRingPage;
    unsafe { initialize(ring, MDRIVER_CONTROL_RING_GENERATION) };
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
    let mut request_id = CONTROL_REQUEST_ID;
    let negotiate = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_NEGOTIATE,
            0,
            [
                u64::from(MDRIVER_CONTROL_VERSION),
                u64::from(MDRIVER_CONTROL_VERSION),
                0,
                0,
            ],
        ),
    );
    if negotiate.status != MDRIVER_CONTROL_STATUS_OK
        || negotiate.values[0] != u64::from(MDRIVER_CONTROL_VERSION)
        || negotiate.values[1] & MDRIVER_CONTROL_CAPABILITIES != MDRIVER_CONTROL_CAPABILITIES
        || negotiate.values[2] > 64
        || negotiate.values[3] != MDRIVER_CONTROL_RING_GENERATION
    {
        initialization_failed(boot_info)
    }

    let mut cursor = 0;
    let mut block_device = None;
    for _ in 0..negotiate.values[2] {
        let enumerated = transact(
            boot_info,
            ring,
            &mut request_id,
            MdriverControlRequest::new(MDRIVER_CONTROL_ENUMERATE, 0, [cursor, 0, 0, 0]),
        );
        if enumerated.status != MDRIVER_CONTROL_STATUS_OK
            || enumerated.device_id == 0
            || enumerated.values[0] != cursor + 1
            || enumerated.values[1] > MDRIVER_DEVICE_KIND_SOUND
            || enumerated.values[2] != MDRIVER_DEVICE_STATE_ONLINE
            || enumerated.values[3]
                & (MDRIVER_DEVICE_FEATURE_DMA_ISOLATED
                    | MDRIVER_DEVICE_FEATURE_INTERRUPT_ACTIVE
                    | MDRIVER_DEVICE_FEATURE_PHYSICAL)
                != MDRIVER_DEVICE_FEATURE_DMA_ISOLATED
                    | MDRIVER_DEVICE_FEATURE_INTERRUPT_ACTIVE
                    | MDRIVER_DEVICE_FEATURE_PHYSICAL
        {
            initialization_failed(boot_info)
        }
        let described = transact(
            boot_info,
            ring,
            &mut request_id,
            MdriverControlRequest::new(MDRIVER_CONTROL_DESCRIBE, enumerated.device_id, [0; 4]),
        );
        if described.status != MDRIVER_CONTROL_STATUS_OK
            || described.device_id != enumerated.device_id
            || described.values[0] != enumerated.values[1]
            || described.values[1] != enumerated.values[2]
            || described.values[2] != enumerated.values[3]
        {
            initialization_failed(boot_info)
        }
        if enumerated.values[1] == MDRIVER_DEVICE_KIND_BLOCK && block_device.is_none() {
            block_device = Some((enumerated.device_id, enumerated.values[3]));
        }
        cursor = enumerated.values[0];
    }
    let end = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_ENUMERATE, 0, [cursor, 0, 0, 0]),
    );
    if end.status != MDRIVER_CONTROL_STATUS_END {
        initialization_failed(boot_info)
    }

    let unsupported = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(u16::MAX, 0, [0; 4]),
    );
    if unsupported.status != MDRIVER_CONTROL_STATUS_UNSUPPORTED_OPERATION {
        initialization_failed(boot_info)
    }
    const PING_COOKIE: u64 = 0x6d6f_6368_694f_5321;
    let ping = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_PING, 0, [PING_COOKIE, 0, 0, 0]),
    );
    if ping.status != MDRIVER_CONTROL_STATUS_OK || ping.values[0] != PING_COOKIE {
        initialization_failed(boot_info)
    }
    let started = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_START_SESSION, 0, [0; 4]),
    );
    if started.status != MDRIVER_CONTROL_STATUS_OK
        || started.values[0] != MDRIVER_CONTROL_RING_GENERATION
    {
        initialization_failed(boot_info)
    }
    let persistent_ping = transact(
        boot_info,
        ring,
        &mut request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_PING, 0, [PING_COOKIE + 1, 0, 0, 0]),
    );
    if persistent_ping.status != MDRIVER_CONTROL_STATUS_OK
        || persistent_ping.values[0] != PING_COOKIE + 1
    {
        initialization_failed(boot_info)
    }
    if let Some((device_id, features)) = block_device {
        verify_block_data_path(boot_info, ring, &mut request_id, device_id, features);
    }
    console_write(boot_info, MDRIVER_PROTOCOL_MESSAGE);
}

fn verify_block_data_path(
    boot_info: &DomainBootInfo,
    ring: *mut SharedRingPage,
    request_id: &mut u64,
    device_id: u32,
    features: u64,
) {
    const REQUIRED_FEATURES: u64 = MDRIVER_DEVICE_FEATURE_BLOCK_READ
        | MDRIVER_DEVICE_FEATURE_BLOCK_WRITE
        | MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH;
    if features & REQUIRED_FEATURES != REQUIRED_FEATURES
        || boot_info.grant_window_size < (MDRIVER_BLOCK_DATA_PAGE + 1) * 4096
    {
        initialization_failed(boot_info)
    }
    let data_address = boot_info.grant_window_start + MDRIVER_BLOCK_DATA_PAGE * 4096;
    let reference = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantCreate,
            data_address,
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
    let opened = transact(
        boot_info,
        ring,
        request_id,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_OPEN_DEVICE,
            device_id,
            [reference, MDRIVER_BLOCK_MAX_TRANSFER, 0, 0],
        ),
    );
    let capacity = opened.values[0];
    let logical_block_size = opened.values[1];
    if opened.status != MDRIVER_CONTROL_STATUS_OK
        || capacity == 0
        || logical_block_size < MDRIVER_BLOCK_SECTOR_SIZE
        || logical_block_size > MDRIVER_BLOCK_MAX_TRANSFER
        || !logical_block_size.is_power_of_two()
        || opened.values[2] < logical_block_size
        || opened.values[3] & REQUIRED_FEATURES != REQUIRED_FEATURES
    {
        initialization_failed(boot_info)
    }

    let read = transact(
        boot_info,
        ring,
        request_id,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_BLOCK_READ,
            device_id,
            [0, logical_block_size, 0, 0],
        ),
    );
    if read.status != MDRIVER_CONTROL_STATUS_OK || read.values[0] != logical_block_size {
        initialization_failed(boot_info)
    }
    let outside = transact(
        boot_info,
        ring,
        request_id,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_BLOCK_READ,
            device_id,
            [capacity, logical_block_size, 0, 0],
        ),
    );
    if outside.status != MDRIVER_CONTROL_STATUS_OUT_OF_RANGE {
        initialization_failed(boot_info)
    }

    if features & MDRIVER_DEVICE_FEATURE_EPHEMERAL != 0 {
        let sectors_per_block = logical_block_size / MDRIVER_BLOCK_SECTOR_SIZE;
        let test_sector = 16_u64.max(sectors_per_block);
        if capacity < test_sector + sectors_per_block {
            initialization_failed(boot_info)
        }
        for index in 0..logical_block_size as usize {
            unsafe { write_volatile((data_address as *mut u8).add(index), block_test_byte(index)) };
        }
        let written = transact(
            boot_info,
            ring,
            request_id,
            MdriverControlRequest::new(
                MDRIVER_CONTROL_BLOCK_WRITE,
                device_id,
                [test_sector, logical_block_size, 0, 0],
            ),
        );
        if written.status != MDRIVER_CONTROL_STATUS_OK || written.values[0] != logical_block_size {
            initialization_failed(boot_info)
        }
        let flushed = transact(
            boot_info,
            ring,
            request_id,
            MdriverControlRequest::new(MDRIVER_CONTROL_BLOCK_FLUSH, device_id, [0; 4]),
        );
        if flushed.status != MDRIVER_CONTROL_STATUS_OK {
            initialization_failed(boot_info)
        }
        for index in 0..logical_block_size as usize {
            unsafe { write_volatile((data_address as *mut u8).add(index), 0) };
        }
        let reread = transact(
            boot_info,
            ring,
            request_id,
            MdriverControlRequest::new(
                MDRIVER_CONTROL_BLOCK_READ,
                device_id,
                [test_sector, logical_block_size, 0, 0],
            ),
        );
        if reread.status != MDRIVER_CONTROL_STATUS_OK || reread.values[0] != logical_block_size {
            initialization_failed(boot_info)
        }
        for index in 0..logical_block_size as usize {
            if unsafe { read_volatile((data_address as *const u8).add(index)) }
                != block_test_byte(index)
            {
                initialization_failed(boot_info)
            }
        }
    }

    let closed = transact(
        boot_info,
        ring,
        request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_CLOSE_DEVICE, device_id, [0; 4]),
    );
    if closed.status != MDRIVER_CONTROL_STATUS_OK {
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
    console_write(boot_info, MDRIVER_BLOCK_MESSAGE);
}

const fn block_test_byte(index: usize) -> u8 {
    (index as u8).wrapping_mul(37).wrapping_add(0x5a)
}

fn transact(
    boot_info: &DomainBootInfo,
    ring: *mut SharedRingPage,
    request_id: &mut u64,
    request: MdriverControlRequest,
) -> MdriverControlResponse {
    let id = *request_id;
    *request_id = request_id.wrapping_add(1);
    let payload = request.encode();
    let message = SharedRingMessage::new(MDRIVER_CONTROL_REQUEST_KIND, 0, id, &payload)
        .unwrap_or_else(|_| initialization_failed(boot_info));
    unsafe { push_request(ring, message) }.unwrap_or_else(|_| initialization_failed(boot_info));
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
        || response.request_id != id
    {
        initialization_failed(boot_info)
    }
    let data = response
        .data()
        .unwrap_or_else(|_| initialization_failed(boot_info));
    let decoded =
        MdriverControlResponse::decode(data).unwrap_or_else(|| initialization_failed(boot_info));
    if decoded.version != MDRIVER_CONTROL_VERSION
        || decoded.operation != request.operation
        || decoded.reserved != 0
    {
        initialization_failed(boot_info)
    }
    decoded
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
