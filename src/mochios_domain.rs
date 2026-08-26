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
    HYPERVISOR_BACKEND_AMD_SVM, HYPERVISOR_BACKEND_INTEL_VMX, MDRIVER_BLOCK_BUFFER_COUNT,
    MDRIVER_BLOCK_BUFFER_FIRST_PAGE, MDRIVER_BLOCK_DATA_PAGE, MDRIVER_BLOCK_REQUEST_KIND,
    MDRIVER_BLOCK_RESPONSE_KIND, MDRIVER_BLOCK_RING_GENERATION, MDRIVER_BLOCK_RING_PAGE,
    MDRIVER_BLOCK_RING_PORT, MDRIVER_CONTROL_IRQ_PORT, MDRIVER_CONTROL_PORT,
    MDRIVER_CONTROL_REQUEST_KIND, MDRIVER_CONTROL_RESPONSE_KIND, MDRIVER_CONTROL_RING_GENERATION,
    MDRIVER_CONTROL_RING_PORT, MDRIVER_DOMAIN_ID,
};
use mnu_abi::mdriver_block::{
    MdriverBlockRequest, MdriverBlockResponse, MDRIVER_BLOCK_FLUSH, MDRIVER_BLOCK_READ,
    MDRIVER_BLOCK_STATUS_OK, MDRIVER_BLOCK_STATUS_OUT_OF_RANGE, MDRIVER_BLOCK_VERSION,
    MDRIVER_BLOCK_WRITE,
};
use mnu_abi::mdriver_control::{
    MdriverControlRequest, MdriverControlResponse, MDRIVER_BLOCK_MAX_TRANSFER,
    MDRIVER_BLOCK_QUEUE_DEPTH, MDRIVER_BLOCK_SECTOR_SIZE, MDRIVER_CONTROL_BLOCK_FLUSH,
    MDRIVER_CONTROL_BLOCK_READ, MDRIVER_CONTROL_BLOCK_WRITE, MDRIVER_CONTROL_CAPABILITIES,
    MDRIVER_CONTROL_CLOSE_DEVICE, MDRIVER_CONTROL_DESCRIBE, MDRIVER_CONTROL_ENUMERATE,
    MDRIVER_CONTROL_NEGOTIATE, MDRIVER_CONTROL_OPEN_BLOCK_QUEUE, MDRIVER_CONTROL_OPEN_DEVICE,
    MDRIVER_CONTROL_PING, MDRIVER_CONTROL_REGISTER_BLOCK_BUFFER, MDRIVER_CONTROL_START_BLOCK_QUEUE,
    MDRIVER_CONTROL_START_SESSION, MDRIVER_CONTROL_STATUS_END, MDRIVER_CONTROL_STATUS_OK,
    MDRIVER_CONTROL_STATUS_OUT_OF_RANGE, MDRIVER_CONTROL_STATUS_UNSUPPORTED_OPERATION,
    MDRIVER_CONTROL_STOP_BLOCK_QUEUE, MDRIVER_CONTROL_VERSION,
    MDRIVER_DEVICE_FEATURE_BLOCK_ASYNC_QUEUE, MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH,
    MDRIVER_DEVICE_FEATURE_BLOCK_READ, MDRIVER_DEVICE_FEATURE_BLOCK_WRITE,
    MDRIVER_DEVICE_FEATURE_DMA_ISOLATED, MDRIVER_DEVICE_FEATURE_EPHEMERAL,
    MDRIVER_DEVICE_FEATURE_INTERRUPT_ACTIVE, MDRIVER_DEVICE_FEATURE_PHYSICAL,
    MDRIVER_DEVICE_KIND_BLOCK, MDRIVER_DEVICE_KIND_SOUND, MDRIVER_DEVICE_STATE_ONLINE,
};
use mnu_abi::shared_ring::{
    initialize, pop_response, push_request, SharedRingMessage, SharedRingPage,
};

static START_MESSAGE: &[u8] = b"mochiOS System Domain entered\n";
static MDRIVER_EVENT_MESSAGE: &[u8] = b"mDriver control Event Channel verified\n";
static MDRIVER_PROTOCOL_MESSAGE: &[u8] = b"mDriver device control protocol ready\n";
static MDRIVER_BLOCK_MESSAGE: &[u8] = b"mDriver block data path ready\n";
static MDRIVER_ASYNC_BLOCK_MESSAGE: &[u8] = b"mDriver asynchronous block queue ready\n";
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
        verify_async_block_queue(boot_info, ring, &mut request_id, device_id, features);
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

fn verify_async_block_queue(
    boot_info: &DomainBootInfo,
    control_ring: *mut SharedRingPage,
    request_id: &mut u64,
    device_id: u32,
    features: u64,
) {
    const REQUIRED_FEATURES: u64 = MDRIVER_DEVICE_FEATURE_BLOCK_READ
        | MDRIVER_DEVICE_FEATURE_BLOCK_WRITE
        | MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH
        | MDRIVER_DEVICE_FEATURE_BLOCK_ASYNC_QUEUE;
    let required_pages = MDRIVER_BLOCK_BUFFER_FIRST_PAGE + MDRIVER_BLOCK_BUFFER_COUNT as u64;
    if features & REQUIRED_FEATURES != REQUIRED_FEATURES
        || MDRIVER_BLOCK_QUEUE_DEPTH != MDRIVER_BLOCK_BUFFER_COUNT as u64
        || boot_info.grant_window_size < required_pages * 4096
    {
        initialization_failed(boot_info)
    }

    let block_ring_address = boot_info.grant_window_start + MDRIVER_BLOCK_RING_PAGE * 4096;
    let block_ring = block_ring_address as *mut SharedRingPage;
    unsafe { initialize(block_ring, MDRIVER_BLOCK_RING_GENERATION) };
    let ring_reference = create_grant(boot_info, block_ring_address);

    let opened = transact(
        boot_info,
        control_ring,
        request_id,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_OPEN_BLOCK_QUEUE,
            device_id,
            [
                ring_reference,
                MDRIVER_BLOCK_RING_GENERATION,
                MDRIVER_BLOCK_QUEUE_DEPTH,
                MDRIVER_BLOCK_MAX_TRANSFER,
            ],
        ),
    );
    let capacity = opened.values[0];
    let logical_block_size = opened.values[1];
    if opened.status != MDRIVER_CONTROL_STATUS_OK
        || capacity == 0
        || logical_block_size < MDRIVER_BLOCK_SECTOR_SIZE
        || logical_block_size > MDRIVER_BLOCK_MAX_TRANSFER
        || !logical_block_size.is_power_of_two()
        || opened.values[2] != MDRIVER_BLOCK_QUEUE_DEPTH
        || opened.values[3] & REQUIRED_FEATURES != REQUIRED_FEATURES
    {
        initialization_failed(boot_info)
    }

    let mut buffer_references = [0_u64; MDRIVER_BLOCK_BUFFER_COUNT];
    for (buffer_id, reference) in buffer_references.iter_mut().enumerate() {
        let address = block_buffer_address(boot_info, buffer_id);
        *reference = create_grant(boot_info, address);
        let registered = transact(
            boot_info,
            control_ring,
            request_id,
            MdriverControlRequest::new(
                MDRIVER_CONTROL_REGISTER_BLOCK_BUFFER,
                device_id,
                [buffer_id as u64, *reference, 0, 0],
            ),
        );
        if registered.status != MDRIVER_CONTROL_STATUS_OK
            || registered.values[0] != buffer_id as u64
        {
            initialization_failed(boot_info)
        }
    }
    let started = transact(
        boot_info,
        control_ring,
        request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_START_BLOCK_QUEUE, device_id, [0; 4]),
    );
    if started.status != MDRIVER_CONTROL_STATUS_OK
        || started.values[0] != MDRIVER_BLOCK_RING_GENERATION
        || started.values[1] != MDRIVER_BLOCK_QUEUE_DEPTH
    {
        initialization_failed(boot_info)
    }

    let transfer = logical_block_size as u32;
    let sectors_per_block = logical_block_size / MDRIVER_BLOCK_SECTOR_SIZE;
    if capacity < sectors_per_block * 3 {
        initialization_failed(boot_info)
    }
    let requests = [
        MdriverBlockRequest::new(MDRIVER_BLOCK_READ, device_id, 0, 0, transfer, 0),
        MdriverBlockRequest::new(
            MDRIVER_BLOCK_READ,
            device_id,
            1,
            sectors_per_block,
            transfer,
            0,
        ),
        MdriverBlockRequest::new(MDRIVER_BLOCK_READ, device_id, 2, capacity, transfer, 0),
        MdriverBlockRequest::new(
            MDRIVER_BLOCK_READ,
            device_id,
            3,
            sectors_per_block * 2,
            transfer,
            0,
        ),
    ];
    let mut ids = [0_u64; MDRIVER_BLOCK_BUFFER_COUNT];
    for (index, request) in requests.iter().copied().enumerate() {
        ids[index] = submit_block_request(boot_info, block_ring, request_id, request);
    }
    notify_block_queue(boot_info);
    let mut seen = [false; MDRIVER_BLOCK_BUFFER_COUNT];
    for _ in 0..MDRIVER_BLOCK_BUFFER_COUNT {
        let (id, response) = receive_block_response(boot_info, block_ring);
        let Some(index) = ids.iter().position(|expected| *expected == id) else {
            initialization_failed(boot_info)
        };
        if seen[index] {
            initialization_failed(boot_info)
        }
        seen[index] = true;
        let expected_status = if index == 2 {
            MDRIVER_BLOCK_STATUS_OUT_OF_RANGE
        } else {
            MDRIVER_BLOCK_STATUS_OK
        };
        verify_block_response(
            boot_info,
            requests[index],
            response,
            expected_status,
            if index == 2 { 0 } else { transfer },
        );
    }

    if features & MDRIVER_DEVICE_FEATURE_EPHEMERAL != 0 {
        let test_sector = 16_u64.max(sectors_per_block);
        if capacity < test_sector + sectors_per_block {
            initialization_failed(boot_info)
        }
        let buffer = block_buffer_address(boot_info, 0);
        for index in 0..transfer as usize {
            unsafe { write_volatile((buffer as *mut u8).add(index), block_test_byte(index)) };
        }
        run_block_request(
            boot_info,
            block_ring,
            request_id,
            MdriverBlockRequest::new(MDRIVER_BLOCK_WRITE, device_id, 0, test_sector, transfer, 0),
            MDRIVER_BLOCK_STATUS_OK,
            transfer,
        );
        run_block_request(
            boot_info,
            block_ring,
            request_id,
            MdriverBlockRequest::new(MDRIVER_BLOCK_FLUSH, device_id, 0, 0, 0, 0),
            MDRIVER_BLOCK_STATUS_OK,
            0,
        );
        for index in 0..transfer as usize {
            unsafe { write_volatile((buffer as *mut u8).add(index), 0) };
        }
        run_block_request(
            boot_info,
            block_ring,
            request_id,
            MdriverBlockRequest::new(MDRIVER_BLOCK_READ, device_id, 0, test_sector, transfer, 0),
            MDRIVER_BLOCK_STATUS_OK,
            transfer,
        );
        for index in 0..transfer as usize {
            if unsafe { read_volatile((buffer as *const u8).add(index)) } != block_test_byte(index)
            {
                initialization_failed(boot_info)
            }
        }
    }

    let stopped = transact(
        boot_info,
        control_ring,
        request_id,
        MdriverControlRequest::new(MDRIVER_CONTROL_STOP_BLOCK_QUEUE, device_id, [0; 4]),
    );
    if stopped.status != MDRIVER_CONTROL_STATUS_OK {
        initialization_failed(boot_info)
    }
    for reference in buffer_references {
        revoke_grant(boot_info, reference);
    }
    revoke_grant(boot_info, ring_reference);
    console_write(boot_info, MDRIVER_ASYNC_BLOCK_MESSAGE);
}

fn block_buffer_address(boot_info: &DomainBootInfo, buffer_id: usize) -> u64 {
    boot_info.grant_window_start + (MDRIVER_BLOCK_BUFFER_FIRST_PAGE + buffer_id as u64) * 4096
}

fn create_grant(boot_info: &DomainBootInfo, address: u64) -> u64 {
    let reference = unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantCreate,
            address,
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
    reference
}

fn revoke_grant(boot_info: &DomainBootInfo, reference: u64) {
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::GrantRevoke,
            reference,
            0,
            0,
        )
    });
}

fn submit_block_request(
    boot_info: &DomainBootInfo,
    ring: *mut SharedRingPage,
    request_id: &mut u64,
    request: MdriverBlockRequest,
) -> u64 {
    let id = *request_id;
    *request_id = request_id.wrapping_add(1);
    let message = SharedRingMessage::new(MDRIVER_BLOCK_REQUEST_KIND, 0, id, &request.encode())
        .unwrap_or_else(|_| initialization_failed(boot_info));
    unsafe { push_request(ring, message) }.unwrap_or_else(|_| initialization_failed(boot_info));
    id
}

fn notify_block_queue(boot_info: &DomainBootInfo) {
    require_success(boot_info, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventSend,
            u64::from(MDRIVER_BLOCK_RING_PORT),
            0,
            0,
        )
    });
    require_port(boot_info, MDRIVER_BLOCK_RING_PORT, unsafe {
        invoke(
            boot_info.hypervisor_backend,
            HypercallNumber::EventWait,
            0,
            0,
            0,
        )
    });
}

fn receive_block_response(
    boot_info: &DomainBootInfo,
    ring: *mut SharedRingPage,
) -> (u64, MdriverBlockResponse) {
    let message =
        unsafe { pop_response(ring) }.unwrap_or_else(|_| initialization_failed(boot_info));
    if message.kind != MDRIVER_BLOCK_RESPONSE_KIND || message.flags != 0 {
        initialization_failed(boot_info)
    }
    let response = MdriverBlockResponse::decode(
        message
            .data()
            .unwrap_or_else(|_| initialization_failed(boot_info)),
    )
    .unwrap_or_else(|| initialization_failed(boot_info));
    if response.version != MDRIVER_BLOCK_VERSION
        || response.reserved0 != 0
        || response.reserved != [0; 2]
    {
        initialization_failed(boot_info)
    }
    (message.request_id, response)
}

fn verify_block_response(
    boot_info: &DomainBootInfo,
    request: MdriverBlockRequest,
    response: MdriverBlockResponse,
    status: u32,
    transferred: u32,
) {
    if response.operation != request.operation
        || response.status != status
        || response.device_id != request.device_id
        || response.buffer_id != request.buffer_id
        || response.sector != request.sector
        || response.transferred != transferred
    {
        initialization_failed(boot_info)
    }
}

fn run_block_request(
    boot_info: &DomainBootInfo,
    ring: *mut SharedRingPage,
    request_id: &mut u64,
    request: MdriverBlockRequest,
    status: u32,
    transferred: u32,
) {
    let id = submit_block_request(boot_info, ring, request_id, request);
    notify_block_queue(boot_info);
    let (response_id, response) = receive_block_response(boot_info, ring);
    if response_id != id {
        initialization_failed(boot_info)
    }
    verify_block_response(boot_info, request, response, status, transferred);
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
