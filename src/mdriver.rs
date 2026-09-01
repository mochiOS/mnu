use core::ptr::copy_nonoverlapping;

use mnu_abi::hypervisor::{
    DOMAIN_FEATURE_EVENT_CHANNEL, DOMAIN_FEATURE_EVENT_POLL, DOMAIN_FEATURE_GRANT_TABLE,
    DOMAIN_FEATURE_SHARED_RING, EVENT_CHANNEL_NO_EVENT, GRANT_FLAG_WRITABLE, GRANT_REF_INVALID,
    HYPERCALL_SUCCESS, HypercallNumber, MDRIVER_BLOCK_DATA_PAGE, MDRIVER_CONTROL_IRQ_PORT,
    MDRIVER_CONTROL_PORT, MDRIVER_CONTROL_REQUEST_KIND, MDRIVER_CONTROL_RESPONSE_KIND,
    MDRIVER_CONTROL_RING_GENERATION, MDRIVER_CONTROL_RING_PORT, MDRIVER_DOMAIN_ID,
    MDRIVER_INSTALL_METADATA_PAGE,
};
use mnu_abi::mdriver_control::{
    MDRIVER_BLOCK_MAX_TRANSFER, MDRIVER_BLOCK_SECTOR_SIZE, MDRIVER_CONTROL_BLOCK_FLUSH,
    MDRIVER_CONTROL_BLOCK_READ, MDRIVER_CONTROL_BLOCK_WRITE, MDRIVER_CONTROL_CAPABILITIES,
    MDRIVER_CONTROL_CLOSE_DEVICE, MDRIVER_CONTROL_DISPLAY_INFO, MDRIVER_CONTROL_ENUMERATE,
    MDRIVER_CONTROL_NEGOTIATE, MDRIVER_CONTROL_OPEN_DEVICE, MDRIVER_CONTROL_OPEN_DISPLAY,
    MDRIVER_CONTROL_OPEN_PARTITION, MDRIVER_CONTROL_PING, MDRIVER_CONTROL_PRESENT_DISPLAY,
    MDRIVER_CONTROL_START_SESSION, MDRIVER_CONTROL_STATUS_END, MDRIVER_CONTROL_STATUS_OK,
    MDRIVER_CONTROL_VERSION, MDRIVER_DEVICE_FEATURE_BLOCK_FLUSH, MDRIVER_DEVICE_FEATURE_BLOCK_READ,
    MDRIVER_DEVICE_FEATURE_BLOCK_WRITE, MDRIVER_DEVICE_FEATURE_DISPLAY_TILE,
    MDRIVER_DEVICE_FEATURE_READ_ONLY, MDRIVER_DEVICE_KIND_BLOCK, MDRIVER_DEVICE_KIND_DISPLAY,
    MDRIVER_DISPLAY_BUFFER_PAGE, MDRIVER_DISPLAY_MAX_TRANSFER, MDRIVER_DISPLAY_PIXEL_BYTES,
    MDRIVER_STORAGE_QUERY_PARTITION_GUIDS, MdriverControlRequest, MdriverControlResponse,
};
use mnu_abi::shared_ring::{
    SharedRingError, SharedRingMessage, SharedRingPage, initialize, pop_response, push_request,
};

use crate::cext::disk::McxDiskOps;
use crate::hypervisor_guest;
use crate::interrupt::spinlock::SpinLock;

const REQUIRED_FEATURES: u64 = DOMAIN_FEATURE_EVENT_CHANNEL
    | DOMAIN_FEATURE_EVENT_POLL
    | DOMAIN_FEATURE_GRANT_TABLE
    | DOMAIN_FEATURE_SHARED_RING;
// mDriver must finish booting its Linux driver environment before it can answer
// the startup handshake. TCG and slow physical firmware can make that take much
// longer than an ordinary control transaction, while every iteration yields the
// vCPU instead of busy-waiting in the System Domain.
const CONTROL_POLL_LIMIT: usize = 10_000_000;
const EIO: i32 = -5;
const ENXIO: i32 = -6;
const EINVAL: i32 = -22;
const EROFS: i32 = -30;
const MOCHIOS_PARTITION_TYPE: [u64; 2] = [0x5300_694f_6d6f_6368, 0x0174_7261_506d_0080];

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
    pub display_device: bool,
}

#[derive(Clone, Copy)]
struct BlockState {
    device_id: u32,
    capacity_sectors: u64,
    logical_block_size: u64,
    features: u64,
    data_address: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayInfo {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub red_offset: u8,
    pub green_offset: u8,
    pub blue_offset: u8,
}

#[derive(Clone, Copy)]
struct DisplayState {
    device_id: u32,
    info: DisplayInfo,
    data_address: u64,
}

#[derive(Clone, Copy)]
struct DisplayCandidate {
    device_id: u32,
    features: u64,
    grant_reference: Option<u32>,
}

const MAX_BLOCK_CANDIDATES: usize = 16;

#[derive(Clone, Copy)]
struct BlockCandidate {
    device_id: u32,
    features: u64,
}

struct Client {
    ring_address: u64,
    request_id: u64,
    block: Option<BlockState>,
    install_metadata_reference: Option<u32>,
    block_candidates: [Option<BlockCandidate>; MAX_BLOCK_CANDIDATES],
    display_candidate: Option<DisplayCandidate>,
    display: Option<DisplayState>,
}

static CLIENT: SpinLock<Option<Client>> = SpinLock::new(None);

pub fn initialize_client() -> Result<Summary, Error> {
    if hypervisor_guest::feature_flags() & REQUIRED_FEATURES != REQUIRED_FEATURES {
        return Err(Error::Unsupported);
    }
    let (grant_start, grant_size) =
        hypervisor_guest::grant_window().ok_or(Error::MissingGrantWindow)?;
    if grant_size
        < (core::cmp::max(MDRIVER_INSTALL_METADATA_PAGE, MDRIVER_DISPLAY_BUFFER_PAGE) + 1) * 4096
    {
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
        install_metadata_reference: None,
        block_candidates: [None; MAX_BLOCK_CANDIDATES],
        display_candidate: None,
        display: None,
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
    let mut block_candidate_count = 0usize;
    let mut display_candidate = None;
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
        if response.values[1] == MDRIVER_DEVICE_KIND_BLOCK
            && block_candidate_count < MAX_BLOCK_CANDIDATES
        {
            client.block_candidates[block_candidate_count] = Some(BlockCandidate {
                device_id: response.device_id,
                features: response.values[3],
            });
            block_candidate_count += 1;
        }
        if response.values[1] == MDRIVER_DEVICE_KIND_DISPLAY && display_candidate.is_none() {
            display_candidate = Some((response.device_id, response.values[3]));
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
    if block_candidate_count != 0 {
        summary.block_read_only = client.block_candidates[..block_candidate_count]
            .iter()
            .flatten()
            .all(|candidate| candidate.features & MDRIVER_DEVICE_FEATURE_READ_ONLY != 0);
    }
    if let Some((candidate, unique_guid)) = find_installed_partition(&mut client)? {
        let block = open_block_device(
            &mut client,
            grant_start,
            candidate.device_id,
            candidate.features,
            Some(unique_guid),
        )?;
        summary.block_device = true;
        summary.block_read_only = block.features & MDRIVER_DEVICE_FEATURE_READ_ONLY != 0;
        client.block = Some(block);
    }
    if let Some((device_id, features)) = display_candidate {
        summary.display_device = features & MDRIVER_DEVICE_FEATURE_DISPLAY_TILE != 0;
        client.display_candidate = Some(DisplayCandidate {
            device_id,
            features,
            grant_reference: None,
        });
    }

    *CLIENT.lock() = Some(client);
    if summary.block_device && !crate::cext::disk::activate_bundle(1, &MDRIVER_DISK_OPS) {
        return Err(Error::Device);
    }
    Ok(summary)
}

fn find_installed_partition(
    client: &mut Client,
) -> Result<Option<(BlockCandidate, [u64; 2])>, Error> {
    let mut selected = None;
    for candidate_index in 0..MAX_BLOCK_CANDIDATES {
        let Some(candidate) = client.block_candidates[candidate_index] else {
            continue;
        };
        for ordinal in 0..128_u64 {
            let response = transact(
                client,
                MdriverControlRequest::new(
                    mnu_abi::mdriver_control::MDRIVER_CONTROL_INSPECT_STORAGE,
                    candidate.device_id,
                    [MDRIVER_STORAGE_QUERY_PARTITION_GUIDS, ordinal, 0, 0],
                ),
            )?;
            if response.status == MDRIVER_CONTROL_STATUS_END {
                break;
            }
            if response.status != MDRIVER_CONTROL_STATUS_OK {
                break;
            }
            if [response.values[0], response.values[1]] != MOCHIOS_PARTITION_TYPE {
                continue;
            }
            let found = (candidate, [response.values[2], response.values[3]]);
            if selected.is_some() {
                return Ok(None);
            }
            selected = Some(found);
        }
    }
    Ok(selected)
}

pub fn storage_control(
    operation: u16,
    device_id: u32,
    mut arguments: [u64; 4],
) -> Result<MdriverControlResponse, Error> {
    use mnu_abi::mdriver_control::{
        MDRIVER_CONTROL_CREATE_PARTITION, MDRIVER_CONTROL_DELETE_PARTITION,
        MDRIVER_CONTROL_INSPECT_STORAGE, MDRIVER_CONTROL_INSTALL_PARTITION,
    };

    // Physical storage discovery is demand-driven. It must never delay the
    // scheduler, service manager, or desktop during boot.
    let initialized = CLIENT.lock().is_some();
    if !initialized {
        initialize_client()?;
    }

    if operation == mnu_abi::STORAGE_CONTROL_LIST_DEVICE {
        let index = usize::try_from(arguments[0]).map_err(|_| Error::Protocol)?;
        if arguments[1..] != [0; 3] {
            return Err(Error::Protocol);
        }
        let guard = CLIENT.lock();
        let client = guard.as_ref().ok_or(Error::Device)?;
        return Ok(match client.block_candidates.iter().flatten().nth(index) {
            Some(candidate) => MdriverControlResponse::new(
                operation,
                MDRIVER_CONTROL_STATUS_OK,
                candidate.device_id,
                [candidate.features, 0, 0, 0],
            ),
            None => MdriverControlResponse::new(operation, MDRIVER_CONTROL_STATUS_END, 0, [0; 4]),
        });
    }
    if !matches!(
        operation,
        MDRIVER_CONTROL_INSPECT_STORAGE
            | MDRIVER_CONTROL_CREATE_PARTITION
            | MDRIVER_CONTROL_DELETE_PARTITION
            | MDRIVER_CONTROL_INSTALL_PARTITION
    ) {
        return Err(Error::Protocol);
    }
    let mut guard = CLIENT.lock();
    let client = guard.as_mut().ok_or(Error::Device)?;
    if client.block.is_some()
        || !client
            .block_candidates
            .iter()
            .flatten()
            .any(|candidate| candidate.device_id == device_id)
    {
        return Err(Error::Device);
    }
    if operation == MDRIVER_CONTROL_INSTALL_PARTITION {
        if arguments[3] != 0 {
            return Err(Error::Protocol);
        }
        arguments[3] = u64::from(install_metadata_reference(client)?);
    }
    transact(
        client,
        MdriverControlRequest::new(operation, device_id, arguments),
    )
}

fn install_metadata_reference(client: &mut Client) -> Result<u32, Error> {
    if let Some(reference) = client.install_metadata_reference {
        return Ok(reference);
    }
    let digest = crate::init::fs::kernel_read_initfs("/install/rootfs.sha256")
        .filter(|bytes| bytes.len() == 32)
        .ok_or(Error::Protocol)?;
    let address = client.ring_address + MDRIVER_INSTALL_METADATA_PAGE * 4096;
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, 4096);
        copy_nonoverlapping(digest.as_ptr(), address as *mut u8, digest.len());
    }
    let reference = hypervisor_guest::invoke(
        HypercallNumber::GrantCreate,
        address,
        u64::from(MDRIVER_DOMAIN_ID),
        0,
    );
    if reference == GRANT_REF_INVALID || reference > u64::from(u32::MAX) {
        return Err(Error::Hypercall);
    }
    let reference = reference as u32;
    client.install_metadata_reference = Some(reference);
    Ok(reference)
}

pub fn block_candidates(out: &mut [(u32, u64)]) -> usize {
    let guard = CLIENT.lock();
    let Some(client) = guard.as_ref() else {
        return 0;
    };
    let mut count = 0;
    for candidate in client.block_candidates.iter().flatten() {
        if count == out.len() {
            break;
        }
        out[count] = (candidate.device_id, candidate.features);
        count += 1;
    }
    count
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
        // Hypervisor Yield schedules another Domain, not another mochiOS
        // thread. Explicitly yield here as well so a slow hardware response
        // cannot starve the service manager and desktop on a single vCPU.
        if crate::task::is_scheduler_enabled() {
            crate::task::yield_now();
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
    partition_guid: Option<[u64; 2]>,
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
    let (operation, arguments) = match partition_guid {
        Some(guid) => (
            MDRIVER_CONTROL_OPEN_PARTITION,
            [reference, MDRIVER_BLOCK_MAX_TRANSFER, guid[0], guid[1]],
        ),
        None => (
            MDRIVER_CONTROL_OPEN_DEVICE,
            [reference, MDRIVER_BLOCK_MAX_TRANSFER, 0, 0],
        ),
    };
    let opened = transact(
        client,
        MdriverControlRequest::new(operation, device_id, arguments),
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
    let start_byte = match lba.checked_mul(512) {
        Some(value) => value,
        None => return EINVAL,
    };
    let end_byte = match start_byte.checked_add(length as u64) {
        Some(value) => value,
        None => return EINVAL,
    };
    let logical = block.logical_block_size as usize;
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

fn ensure_display(client: &mut Client) -> Result<DisplayState, Error> {
    if let Some(display) = client.display {
        return Ok(display);
    }
    let mut candidate = client.display_candidate.ok_or(Error::Device)?;
    if candidate.features & MDRIVER_DEVICE_FEATURE_DISPLAY_TILE == 0 {
        return Err(Error::Device);
    }
    let grant_reference = match candidate.grant_reference {
        Some(reference) => reference,
        None => {
            let Some(grant_start) = hypervisor_guest::grant_window().map(|window| window.0) else {
                return Err(Error::MissingGrantWindow);
            };
            let reference = hypervisor_guest::invoke(
                HypercallNumber::GrantCreate,
                grant_start + MDRIVER_DISPLAY_BUFFER_PAGE * 4096,
                u64::from(MDRIVER_DOMAIN_ID),
                GRANT_FLAG_WRITABLE,
            );
            if reference == GRANT_REF_INVALID || reference > u64::from(u32::MAX) {
                return Err(Error::Hypercall);
            }
            candidate.grant_reference = Some(reference as u32);
            client.display_candidate = Some(candidate);
            reference as u32
        }
    };
    let opened = transact(
        client,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_OPEN_DISPLAY,
            candidate.device_id,
            [u64::from(grant_reference), 0, 0, 0],
        ),
    )?;
    if opened.status != MDRIVER_CONTROL_STATUS_OK
        || opened.values[0] != MDRIVER_DISPLAY_MAX_TRANSFER
        || opened.values[1] != MDRIVER_DISPLAY_PIXEL_BYTES
    {
        return Err(Error::Device);
    }
    let response = transact(
        client,
        MdriverControlRequest::new(MDRIVER_CONTROL_DISPLAY_INFO, candidate.device_id, [0; 4]),
    )?;
    let format = response.values[3];
    let width = u32::try_from(response.values[0]).map_err(|_| Error::Protocol)?;
    let height = u32::try_from(response.values[1]).map_err(|_| Error::Protocol)?;
    let line_bytes = u32::try_from(response.values[2]).map_err(|_| Error::Protocol)?;
    if response.status != MDRIVER_CONTROL_STATUS_OK
        || width == 0
        || height == 0
        || line_bytes < width.saturating_mul(MDRIVER_DISPLAY_PIXEL_BYTES as u32)
        || line_bytes % MDRIVER_DISPLAY_PIXEL_BYTES as u32 != 0
        || format as u8 != MDRIVER_DISPLAY_PIXEL_BYTES as u8 * 8
        || (format >> 8) as u8 != 16
        || (format >> 16) as u8 != 8
        || (format >> 24) as u8 != 0
    {
        return Err(Error::Protocol);
    }
    let display = DisplayState {
        device_id: candidate.device_id,
        info: DisplayInfo {
            width,
            height,
            stride: line_bytes / MDRIVER_DISPLAY_PIXEL_BYTES as u32,
            red_offset: (format >> 8) as u8,
            green_offset: (format >> 16) as u8,
            blue_offset: (format >> 24) as u8,
        },
        data_address: hypervisor_guest::grant_window()
            .ok_or(Error::MissingGrantWindow)?
            .0
            + MDRIVER_DISPLAY_BUFFER_PAGE * 4096,
    };
    client.display = Some(display);
    Ok(display)
}

pub fn display_info() -> Result<DisplayInfo, Error> {
    let mut guard = CLIENT.lock();
    let client = guard.as_mut().ok_or(Error::Device)?;
    ensure_display(client).map(|display| display.info)
}

pub fn present_display(
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    pixels: &[u8],
) -> Result<(), Error> {
    let expected = usize::try_from(width)
        .ok()
        .and_then(|width| {
            usize::try_from(height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .and_then(|pixels| pixels.checked_mul(MDRIVER_DISPLAY_PIXEL_BYTES as usize))
        .ok_or(Error::Protocol)?;
    if width == 0 || height == 0 || expected != pixels.len() || expected > 4096 {
        return Err(Error::Protocol);
    }
    let mut guard = CLIENT.lock();
    let client = guard.as_mut().ok_or(Error::Device)?;
    let display = ensure_display(client)?;
    if x.checked_add(width)
        .is_none_or(|right| right > display.info.width)
        || y.checked_add(height)
            .is_none_or(|bottom| bottom > display.info.height)
    {
        return Err(Error::Protocol);
    }
    unsafe {
        copy_nonoverlapping(
            pixels.as_ptr(),
            display.data_address as *mut u8,
            pixels.len(),
        )
    };
    let response = transact(
        client,
        MdriverControlRequest::new(
            MDRIVER_CONTROL_PRESENT_DISPLAY,
            display.device_id,
            [
                u64::from(x),
                u64::from(y),
                u64::from(width),
                u64::from(height),
            ],
        ),
    )?;
    if response.status == MDRIVER_CONTROL_STATUS_OK {
        Ok(())
    } else {
        Err(Error::Device)
    }
}

/// Draws a bounded startup marker through mDriver after the control protocol
/// is usable. The userspace display service replaces it during normal boot.
pub fn present_startup_marker(color: u32) -> Result<(), Error> {
    const MARKER_WIDTH: u32 = 512;
    const MARKER_HEIGHT: u32 = 128;
    let info = display_info()?;
    let width = info.width.min(MARKER_WIDTH);
    let height = info.height.min(MARKER_HEIGHT);
    if width == 0 || height == 0 {
        return Err(Error::Protocol);
    }
    let origin_x = info.width.saturating_sub(width) / 2;
    let origin_y = info.height.saturating_sub(height) / 2;
    let row_bytes = usize::try_from(width)
        .ok()
        .and_then(|width| width.checked_mul(MDRIVER_DISPLAY_PIXEL_BYTES as usize))
        .ok_or(Error::Protocol)?;
    let rows_per_tile = (4096 / row_bytes).max(1);
    let mut tile = [0u8; 4096];
    let pixel = color.to_le_bytes();
    for chunk in tile.chunks_exact_mut(MDRIVER_DISPLAY_PIXEL_BYTES as usize) {
        chunk.copy_from_slice(&pixel);
    }
    let mut y = 0usize;
    while y < height as usize {
        let rows = core::cmp::min(height as usize - y, rows_per_tile);
        let byte_len = row_bytes.checked_mul(rows).ok_or(Error::Protocol)?;
        present_display(
            origin_x,
            origin_y + u32::try_from(y).map_err(|_| Error::Protocol)?,
            width,
            u32::try_from(rows).map_err(|_| Error::Protocol)?,
            &tile[..byte_len],
        )?;
        y += rows;
    }
    Ok(())
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
