use core::ptr::copy_nonoverlapping;

use mnu_abi::hypervisor::{
    HypercallNumber, DOMAIN_FEATURE_EVENT_CHANNEL, DOMAIN_FEATURE_EVENT_POLL,
    DOMAIN_FEATURE_GRANT_TABLE, DOMAIN_FEATURE_SHARED_RING, EVENT_CHANNEL_NO_EVENT,
    GRANT_FLAG_WRITABLE, GRANT_REF_INVALID, HYPERCALL_SUCCESS, MDRIVER_BLOCK_DATA_PAGE,
    MDRIVER_CONTROL_IRQ_PORT, MDRIVER_CONTROL_PORT, MDRIVER_CONTROL_REQUEST_KIND,
    MDRIVER_CONTROL_RESPONSE_KIND, MDRIVER_CONTROL_RING_GENERATION, MDRIVER_CONTROL_RING_PORT,
    MDRIVER_DOMAIN_ID,
};
use mnu_abi::mdriver_control::{
    MdriverControlRequest, MdriverControlResponse, MDRIVER_BLOCK_MAX_TRANSFER,
    MDRIVER_BLOCK_SECTOR_SIZE, MDRIVER_CONTROL_BLOCK_FLUSH, MDRIVER_CONTROL_BLOCK_READ,
    MDRIVER_CONTROL_BLOCK_WRITE, MDRIVER_CONTROL_CAPABILITIES, MDRIVER_CONTROL_CLOSE_DEVICE,
    MDRIVER_CONTROL_ENUMERATE, MDRIVER_CONTROL_NEGOTIATE, MDRIVER_CONTROL_OPEN_DEVICE,
    MDRIVER_CONTROL_PING, MDRIVER_CONTROL_START_SESSION, MDRIVER_CONTROL_STATUS_END,
    MDRIVER_CONTROL_STATUS_OK, MDRIVER_CONTROL_VERSION, MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH,
    MDRIVER_DEVICE_FEATURE_BLOCK_READ, MDRIVER_DEVICE_FEATURE_BLOCK_WRITE,
    MDRIVER_DEVICE_FEATURE_READ_ONLY, MDRIVER_DEVICE_KIND_BLOCK,
};
use mnu_abi::shared_ring::{
    initialize, pop_response, push_request, SharedRingError, SharedRingMessage, SharedRingPage,
};

use crate::cext::disk::McxDiskOps;
use crate::hypervisor_guest;
use crate::interrupt::spinlock::SpinLock;

const REQUIRED_FEATURES: u64 = DOMAIN_FEATURE_EVENT_CHANNEL
    | DOMAIN_FEATURE_EVENT_POLL
    | DOMAIN_FEATURE_GRANT_TABLE
    | DOMAIN_FEATURE_SHARED_RING;
const CONTROL_POLL_LIMIT: usize = 200_000;
const EIO: i32 = -5;
const ENXIO: i32 = -6;
const EINVAL: i32 = -22;
const EROFS: i32 = -30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unsupported,
    MissingGrantWindow,
    Hypercall,
    Timeout,
    Ring,
    Protocol,
    Device,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Summary {
    pub device_count: u32,
    pub block_device: bool,
    pub block_read_only: bool,
}

#[derive(Clone, Copy)]
struct BlockState {
    device_id: u32,
    capacity_sectors: u64,
    logical_block_size: u64,
    features: u64,
    data_address: u64,
}

struct Client {
    ring_address: u64,
    request_id: u64,
    block: Option<BlockState>,
}

static CLIENT: SpinLock<Option<Client>> = SpinLock::new(None);

pub fn initialize_client() -> Result<Summary, Error> {
    if hypervisor_guest::feature_flags() & REQUIRED_FEATURES != REQUIRED_FEATURES {
        return Err(Error::Unsupported);
    }
    let (grant_start, grant_size) =
        hypervisor_guest::grant_window().ok_or(Error::MissingGrantWindow)?;
    if grant_size < (MDRIVER_BLOCK_DATA_PAGE + 1) * 4096 {
        return Err(Error::MissingGrantWindow);
    }

    handshake_port(MDRIVER_CONTROL_PORT)?;
    handshake_port(MDRIVER_CONTROL_IRQ_PORT)?;

    let ring = grant_start as *mut SharedRingPage;
    unsafe { initialize(ring, MDRIVER_CONTROL_RING_GENERATION) };
    let ring_reference = hypervisor_guest::invoke(
        HypercallNumber::GrantCreate,
        grant_start,
        u64::from(MDRIVER_DOMAIN_ID),
        GRANT_FLAG_WRITABLE,
    );
    if ring_reference == GRANT_REF_INVALID || ring_reference > u64::from(u32::MAX) {
        return Err(Error::Hypercall);
    }

    let mut client = Client {
        ring_address: grant_start,
        request_id: 1,
        block: None,
    };
    let negotiated = transact(
        &mut client,
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
    )?;
    if negotiated.status != MDRIVER_CONTROL_STATUS_OK
        || negotiated.values[0] != u64::from(MDRIVER_CONTROL_VERSION)
        || negotiated.values[1] & MDRIVER_CONTROL_CAPABILITIES != MDRIVER_CONTROL_CAPABILITIES
        || negotiated.values[2] > u64::from(u32::MAX)
        || negotiated.values[3] != MDRIVER_CONTROL_RING_GENERATION
    {
        return Err(Error::Protocol);
    }

    let device_count = negotiated.values[2] as u32;
    let mut block_candidate = None;
    let mut cursor = 0_u64;
    for _ in 0..device_count {
        let response = transact(
            &mut client,
            MdriverControlRequest::new(MDRIVER_CONTROL_ENUMERATE, 0, [cursor, 0, 0, 0]),
        )?;
        if response.status != MDRIVER_CONTROL_STATUS_OK
            || response.device_id == 0
            || response.values[0] != cursor + 1
        {
            return Err(Error::Protocol);
        }
        if response.values[1] == MDRIVER_DEVICE_KIND_BLOCK && block_candidate.is_none() {
            block_candidate = Some((response.device_id, response.values[3]));
        }
        cursor = response.values[0];
    }
    let end = transact(
        &mut client,
        MdriverControlRequest::new(MDRIVER_CONTROL_ENUMERATE, 0, [cursor, 0, 0, 0]),
    )?;
    if end.status != MDRIVER_CONTROL_STATUS_END {
        return Err(Error::Protocol);
    }
    const PING_COOKIE: u64 = 0x6d6f_6368_694f_5321;
    let ping = transact(
        &mut client,
        MdriverControlRequest::new(MDRIVER_CONTROL_PING, 0, [PING_COOKIE, 0, 0, 0]),
    )?;
    if ping.status != MDRIVER_CONTROL_STATUS_OK || ping.values[0] != PING_COOKIE {
        return Err(Error::Protocol);
    }
    let started = transact(
        &mut client,
        MdriverControlRequest::new(MDRIVER_CONTROL_START_SESSION, 0, [0; 4]),
    )?;
    if started.status != MDRIVER_CONTROL_STATUS_OK
        || started.values[0] != MDRIVER_CONTROL_RING_GENERATION
    {
        return Err(Error::Protocol);
    }

    let mut summary = Summary {
        device_count,
        ..Summary::default()
    };
    if let Some((device_id, features)) = block_candidate {
        let block = open_block_device(&mut client, grant_start, device_id, features)?;
        summary.block_device = true;
        summary.block_read_only = block.features & MDRIVER_DEVICE_FEATURE_READ_ONLY != 0;
        client.block = Some(block);
    }

    *CLIENT.lock() = Some(client);
    if summary.block_device && !crate::cext::disk::activate_bundle(1, &MDRIVER_DISK_OPS) {
        return Err(Error::Device);
    }
    Ok(summary)
}

fn handshake_port(port: u32) -> Result<(), Error> {
    if hypervisor_guest::invoke(HypercallNumber::EventSend, u64::from(port), 0, 0)
        != HYPERCALL_SUCCESS
    {
        return Err(Error::Hypercall);
    }
    wait_for_port(port)
}

fn wait_for_port(expected: u32) -> Result<(), Error> {
    for _ in 0..CONTROL_POLL_LIMIT {
        let port = hypervisor_guest::invoke(HypercallNumber::EventPoll, 0, 0, 0);
        if port == u64::from(expected) {
            return Ok(());
        }
        if port != EVENT_CHANNEL_NO_EVENT {
            continue;
        }
        if hypervisor_guest::invoke(HypercallNumber::Yield, 0, 0, 0) != HYPERCALL_SUCCESS {
            return Err(Error::Hypercall);
        }
    }
    Err(Error::Timeout)
}

fn transact(
    client: &mut Client,
    request: MdriverControlRequest,
) -> Result<MdriverControlResponse, Error> {
    let id = client.request_id;
    client.request_id = client.request_id.wrapping_add(1);
    let message = SharedRingMessage::new(MDRIVER_CONTROL_REQUEST_KIND, 0, id, &request.encode())
        .map_err(|_| Error::Ring)?;
    let ring = client.ring_address as *mut SharedRingPage;
    unsafe { push_request(ring, message) }.map_err(|_| Error::Ring)?;
    if hypervisor_guest::invoke(
        HypercallNumber::EventSend,
        u64::from(MDRIVER_CONTROL_RING_PORT),
        0,
        0,
    ) != HYPERCALL_SUCCESS
    {
        return Err(Error::Hypercall);
    }
    wait_for_port(MDRIVER_CONTROL_RING_PORT)?;
    let message = unsafe { pop_response(ring) }.map_err(|error| match error {
        SharedRingError::Empty => Error::Timeout,
        _ => Error::Ring,
    })?;
    if message.kind != MDRIVER_CONTROL_RESPONSE_KIND
        || message.flags != 0
        || message.request_id != id
    {
        return Err(Error::Protocol);
    }
    let response = MdriverControlResponse::decode(message.data().map_err(|_| Error::Ring)?)
        .ok_or(Error::Protocol)?;
    if response.version != MDRIVER_CONTROL_VERSION
        || response.operation != request.operation
        || response.reserved != 0
    {
        return Err(Error::Protocol);
    }
    Ok(response)
}

fn open_block_device(
    client: &mut Client,
    grant_start: u64,
    device_id: u32,
    features: u64,
) -> Result<BlockState, Error> {
    if features & MDRIVER_DEVICE_FEATURE_BLOCK_READ == 0 {
        return Err(Error::Device);
    }
    let data_address = grant_start + MDRIVER_BLOCK_DATA_PAGE * 4096;
    let reference = hypervisor_guest::invoke(
        HypercallNumber::GrantCreate,
        data_address,
        u64::from(MDRIVER_DOMAIN_ID),
        GRANT_FLAG_WRITABLE,
    );
    if reference == GRANT_REF_INVALID || reference > u64::from(u32::MAX) {
        return Err(Error::Hypercall);
    }
    let opened = transact(
        client,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_OPEN_DEVICE,
            device_id,
            [reference, MDRIVER_BLOCK_MAX_TRANSFER, 0, 0],
        ),
    )?;
    let logical_block_size = opened.values[1];
    if opened.status != MDRIVER_CONTROL_STATUS_OK
        || opened.values[0] == 0
        || !(MDRIVER_BLOCK_SECTOR_SIZE..=MDRIVER_BLOCK_MAX_TRANSFER).contains(&logical_block_size)
        || !logical_block_size.is_power_of_two()
        || opened.values[2] < logical_block_size
        || opened.values[3] & MDRIVER_DEVICE_FEATURE_BLOCK_READ == 0
    {
        return Err(Error::Device);
    }
    Ok(BlockState {
        device_id,
        capacity_sectors: opened.values[0],
        logical_block_size,
        features: opened.values[3],
        data_address,
    })
}

extern "C" fn disk_probe() -> i32 {
    if CLIENT
        .lock()
        .as_ref()
        .and_then(|client| client.block)
        .is_some()
    {
        1
    } else {
        ENXIO
    }
}

extern "C" fn disk_read(disk_id: u32, lba: u64, buffer: *mut u8, length: usize) -> i32 {
    if disk_id != 0 || buffer.is_null() || length == 0 || length % 512 != 0 {
        return EINVAL;
    }
    let mut guard = CLIENT.lock();
    let Some(client) = guard.as_mut() else {
        return ENXIO;
    };
    let Some(block) = client.block else {
        return ENXIO;
    };
    unsafe { transfer(client, block, lba, buffer, length, false) }
}

extern "C" fn disk_write(disk_id: u32, lba: u64, buffer: *const u8, length: usize) -> i32 {
    if disk_id != 0 || buffer.is_null() || length == 0 || length % 512 != 0 {
        return EINVAL;
    }
    let mut guard = CLIENT.lock();
    let Some(client) = guard.as_mut() else {
        return ENXIO;
    };
    let Some(block) = client.block else {
        return ENXIO;
    };
    if block.features & MDRIVER_DEVICE_FEATURE_BLOCK_WRITE == 0 {
        return EROFS;
    }
    unsafe { transfer(client, block, lba, buffer.cast_mut(), length, true) }
}

extern "C" fn disk_flush(disk_id: u32) -> i32 {
    if disk_id != 0 {
        return EINVAL;
    }
    let mut guard = CLIENT.lock();
    let Some(client) = guard.as_mut() else {
        return ENXIO;
    };
    let Some(block) = client.block else {
        return ENXIO;
    };
    if block.features & MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH == 0 {
        return 0;
    }
    match transact(
        client,
        MdriverControlRequest::new(MDRIVER_CONTROL_BLOCK_FLUSH, block.device_id, [0; 4]),
    ) {
        Ok(response) if response.status == MDRIVER_CONTROL_STATUS_OK => 0,
        _ => EIO,
    }
}

unsafe fn transfer(
    client: &mut Client,
    block: BlockState,
    lba: u64,
    buffer: *mut u8,
    length: usize,
    write: bool,
) -> i32 {
    let Some(request_end) = lba.checked_add((length / 512) as u64) else {
        return EINVAL;
    };
    if request_end > block.capacity_sectors {
        return EIO;
    }
    let logical = block.logical_block_size as usize;
    let start_byte = match lba.checked_mul(512) {
        Some(value) => value,
        None => return EINVAL,
    };
    let end_byte = match start_byte.checked_add(length as u64) {
        Some(value) => value,
        None => return EINVAL,
    };
    let mut block_byte = start_byte / block.logical_block_size * block.logical_block_size;
    while block_byte < end_byte {
        let copy_start = start_byte.max(block_byte);
        let copy_end = end_byte.min(block_byte + block.logical_block_size);
        let copy_length = (copy_end - copy_start) as usize;
        let shared_offset = (copy_start - block_byte) as usize;
        let caller_offset = (copy_start - start_byte) as usize;
        let whole_block = shared_offset == 0 && copy_length == logical;

        if !write || !whole_block {
            if control_io(
                client,
                block,
                MDRIVER_CONTROL_BLOCK_READ,
                block_byte / 512,
                logical,
            ) != 0
            {
                return EIO;
            }
        }
        if write {
            unsafe {
                copy_nonoverlapping(
                    buffer.add(caller_offset),
                    (block.data_address as *mut u8).add(shared_offset),
                    copy_length,
                )
            };
            if control_io(
                client,
                block,
                MDRIVER_CONTROL_BLOCK_WRITE,
                block_byte / 512,
                logical,
            ) != 0
            {
                return EIO;
            }
        } else {
            unsafe {
                copy_nonoverlapping(
                    (block.data_address as *const u8).add(shared_offset),
                    buffer.add(caller_offset),
                    copy_length,
                )
            };
        }
        block_byte += block.logical_block_size;
    }
    0
}

fn control_io(
    client: &mut Client,
    block: BlockState,
    operation: u16,
    lba: u64,
    length: usize,
) -> i32 {
    if length > MDRIVER_BLOCK_MAX_TRANSFER as usize {
        return EINVAL;
    }
    match transact(
        client,
        MdriverControlRequest::new(operation, block.device_id, [lba, length as u64, 0, 0]),
    ) {
        Ok(response)
            if response.status == MDRIVER_CONTROL_STATUS_OK
                && response.values[0] == length as u64 =>
        {
            0
        }
        _ => EIO,
    }
}

pub fn close_block_device() -> Result<(), Error> {
    let mut guard = CLIENT.lock();
    let client = guard.as_mut().ok_or(Error::Device)?;
    let block = client.block.ok_or(Error::Device)?;
    let response = transact(
        client,
        MdriverControlRequest::new(MDRIVER_CONTROL_CLOSE_DEVICE, block.device_id, [0; 4]),
    )?;
    if response.status != MDRIVER_CONTROL_STATUS_OK {
        return Err(Error::Device);
    }
    client.block = None;
    Ok(())
}

static MDRIVER_DISK_OPS: McxDiskOps = McxDiskOps {
    probe: disk_probe,
    read_sector: disk_read,
    write_sector: disk_write,
    flush: disk_flush,
};
