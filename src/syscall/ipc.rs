use crate::interrupt::spinlock::{SpinLock, SpinLockGuard};
use alloc::alloc::{alloc, Layout};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::task::{FileHandle, FileHandleCap};

use super::{EACCES, EAGAIN, EBADF, EFAULT, EINVAL, EMSGSIZE, ENOSPC};

const MAX_THREADS: usize = crate::task::ThreadQueue::MAX_THREADS;
const MAILBOX_CAP: usize = 64;
const MESSAGE_CACHE_CAP: usize = MAILBOX_CAP;
const MAX_MSG_SIZE: usize = crate::config::IPC_MESSAGE_CAPACITY;
const MAX_EXT_PAGES: usize = 262_144;
const MAX_INLINE_EXT_PAGES: usize = 16;
const MAX_FILE_HANDLES: usize = mnu_abi::IPC_MAX_FILE_HANDLES;

/// endpoint ベース IPC への移行用ハンドル
///
/// 既存の thread-ID ベースの mailbox を直接露出せず、世代番号付きの endpoint を
/// 受け渡すための薄いラッパとして使う。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpcEndpoint {
    pub thread_id: u64,
    pub slot: u16,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointRights(u8);

impl EndpointRights {
    pub const SEND: Self = Self(0x1);
    pub const RECV: Self = Self(0x2);
    pub const CREATE: Self = Self(0x4);
    pub const MANAGE: Self = Self(0x8);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

#[derive(Clone, Copy, Debug)]
struct EndpointRecord {
    thread_id: u64,
    slot: u16,
    generation: u64,
    rights: EndpointRights,
}

// Endpoint handles and legacy thread IDs are both accepted by IPC syscalls.
// Keep handles in a disjoint opaque range so a thread ID can never resolve to
// an unrelated endpoint merely because both counters reached the same value.
// The sender handle is carried in the upper 32 bits of a successful syscall
// result, so it must also stay below bit 31 to keep that result non-negative.
const ENDPOINT_HANDLE_BASE: u64 = 0x4000_0000;
const ENDPOINT_HANDLE_LIMIT: u64 = 0x7fff_ffff;
static NEXT_ENDPOINT_HANDLE: AtomicU64 = AtomicU64::new(ENDPOINT_HANDLE_BASE);
static NEXT_CALL_ID: AtomicU64 = AtomicU64::new(1);
static ENDPOINTS: Mutex<Option<BTreeMap<u64, EndpointRecord>>> = Mutex::new(None);
static THREAD_DEFAULT_ENDPOINTS: Mutex<Option<BTreeMap<u64, u64>>> = Mutex::new(None);

pub fn endpoint_for_thread(thread_id: u64) -> Option<IpcEndpoint> {
    let (slot, generation) = crate::task::thread_slot_index_and_generation_by_u64(thread_id)?;
    Some(IpcEndpoint {
        thread_id,
        slot: slot as u16,
        generation,
    })
}

/// 指定スレッドに紐づく既定 endpoint handle を返す。
///
/// まだ handle がなければ新規に作成する。
pub fn ensure_endpoint_handle_for_thread(thread_id: u64) -> Option<u64> {
    ensure_endpoint_for_thread(thread_id)
}

pub fn endpoint_is_valid(endpoint: IpcEndpoint) -> bool {
    match crate::task::thread_slot_index_and_generation_by_u64(endpoint.thread_id) {
        Some((slot, generation)) => {
            slot as u16 == endpoint.slot && generation == endpoint.generation
        }
        None => false,
    }
}

pub fn endpoint_rights_for_process(process_id: u64) -> EndpointRights {
    let process_id = crate::task::ProcessId::from_u64(process_id);
    let mut rights = EndpointRights::empty();
    if crate::task::process::process_has_capability(
        process_id,
        crate::capability::Capability::IpcClient,
    ) {
        rights = rights.union(EndpointRights::SEND);
    }
    if crate::task::process::process_has_capability(
        process_id,
        crate::capability::Capability::IpcServer,
    ) {
        rights = rights.union(EndpointRights::RECV);
    }
    rights
}

fn with_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, EndpointRecord>) -> R) -> R {
    let mut guard = ENDPOINTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn with_default_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, u64>) -> R) -> R {
    let mut guard = THREAD_DEFAULT_ENDPOINTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn endpoint_record_is_valid(record: &EndpointRecord) -> bool {
    match crate::task::thread_slot_index_and_generation_by_u64(record.thread_id) {
        Some((slot, generation)) => slot as u16 == record.slot && generation == record.generation,
        None => false,
    }
}

fn endpoint_record_from_handle(handle: u64) -> Option<EndpointRecord> {
    with_endpoints_mut(|endpoints| endpoints.get(&handle).copied())
        .filter(|record| endpoint_record_is_valid(record))
}

pub fn endpoint_alive(handle: u64) -> u64 {
    if handle != 0 && endpoint_record_from_handle(handle).is_some() {
        super::SUCCESS
    } else {
        super::EINVAL
    }
}

pub fn endpoint_owner_process(handle: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::ProcessInspect,
    ]) {
        return EACCES;
    }
    let Some(record) = endpoint_record_from_handle(handle) else {
        return EINVAL;
    };
    crate::task::thread_to_process_id(record.thread_id)
        .map(|process_id| process_id.as_u64())
        .unwrap_or(EINVAL)
}

pub fn endpoint_is_owned_by(handle: u64, process_id: crate::task::ProcessId) -> bool {
    let Some(record) = endpoint_record_from_handle(handle) else {
        return false;
    };
    crate::task::thread_to_process_id(record.thread_id) == Some(process_id)
        && record.rights.contains(EndpointRights::RECV)
}

fn endpoint_rights_for_thread(thread_id: u64) -> EndpointRights {
    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return EndpointRights::empty();
    };
    endpoint_rights_for_process(pid.as_u64())
}

fn endpoint_handle_for_thread(thread_id: u64) -> Option<u64> {
    let handle = with_default_endpoints_mut(|defaults| defaults.get(&thread_id).copied());
    let Some(handle) = handle else {
        return None;
    };
    if endpoint_record_from_handle(handle).is_some() {
        Some(handle)
    } else {
        with_default_endpoints_mut(|defaults| {
            if defaults.get(&thread_id).copied() == Some(handle) {
                defaults.remove(&thread_id);
            }
        });
        None
    }
}

fn ensure_endpoint_for_thread(thread_id: u64) -> Option<u64> {
    if let Some(handle) = endpoint_handle_for_thread(thread_id) {
        return Some(handle);
    }
    let (slot, generation) = crate::task::thread_slot_index_and_generation_by_u64(thread_id)?;
    let rights = endpoint_rights_for_thread(thread_id);
    let handle = NEXT_ENDPOINT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle > ENDPOINT_HANDLE_LIMIT {
        return None;
    }
    let record = EndpointRecord {
        thread_id,
        slot: slot as u16,
        generation,
        rights,
    };
    with_endpoints_mut(|endpoints| {
        endpoints.insert(handle, record);
    });
    with_default_endpoints_mut(|defaults| {
        defaults.insert(thread_id, handle);
    });
    Some(handle)
}

pub fn resolve_endpoint_handle(dest: u64) -> Option<u64> {
    endpoint_record_from_handle(dest).map(|record| record.thread_id)
}

pub fn resolve_sender_thread_id(sender: u64) -> Option<u64> {
    resolve_endpoint_handle(sender)
        .or_else(|| crate::task::thread_slot_index_and_generation_by_u64(sender).map(|_| sender))
}

pub fn create(flags: u64, _reserved: u64) -> u64 {
    if flags != 0 {
        return EINVAL;
    }
    let thread_id = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    ensure_endpoint_for_thread(thread_id).unwrap_or(EINVAL)
}

pub fn call(
    dest_endpoint_handle: u64,
    req_ptr: u64,
    req_len: u64,
    reply_ptr: u64,
    reply_len: u64,
) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let dest_record = match endpoint_record_from_handle(dest_endpoint_handle) {
        Some(record) => record,
        None => return EINVAL,
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return EACCES;
    }
    let dest_thread_id = dest_record.thread_id;
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    #[cfg(feature = "performance-instrumentation")]
    let round_trip_start = crate::performance::timestamp();
    let sent = loop {
        let status = send_call_to_thread_id(dest_thread_id, sender, call_id, req_ptr, req_len);
        if status != EAGAIN {
            break status;
        }
        crate::task::yield_now();
    };
    if sent != 0 {
        return sent;
    }
    let result = recv_blocking_reply_for_thread(
        caller,
        caller,
        dest_endpoint_handle,
        call_id,
        reply_ptr,
        reply_len,
    );
    #[cfg(feature = "performance-instrumentation")]
    if (result as i64) >= 0 {
        crate::performance::record_latency(
            crate::performance::LatencyMetric::IpcSmallRoundTrip,
            round_trip_start,
        );
    }
    result
}

/// Performs a synchronous IPC call whose request carries rights-restricted
/// file handles. Replies use the existing byte-only reply path.
pub fn call_handles(
    dest_endpoint_handle: u64,
    req_ptr: u64,
    req_len: u64,
    reply_ptr: u64,
    reply_len: u64,
    handles_ptr: u64,
) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let Some(dest_record) = endpoint_record_from_handle(dest_endpoint_handle) else {
        return EINVAL;
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return EACCES;
    }
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let sender = match ensure_endpoint_for_thread(caller) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let sent = loop {
        let attachments = match decode_outgoing_file_handles(handles_ptr) {
            Ok(handles) => handles,
            Err(error) => return error,
        };
        let status = send_to_thread_id_with_kind(
            dest_record.thread_id,
            sender,
            call_id,
            req_ptr,
            req_len,
            false,
            true,
            attachments,
        );
        if status != EAGAIN {
            break status;
        }
        crate::task::yield_now();
    };
    if sent != 0 {
        return sent;
    }
    recv_blocking_reply_for_thread(
        caller,
        caller,
        dest_endpoint_handle,
        call_id,
        reply_ptr,
        reply_len,
    )
}

pub fn reply(dest_thread_id: u64, buf_ptr: u64, len: u64) -> u64 {
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let caller_handle = match ensure_endpoint_for_thread(current) {
        Some(handle) => handle,
        None => return EINVAL,
    };
    let target = {
        let boxes = lock_mailboxes();
        let (idx, _) = match crate::task::thread_slot_index_and_generation_by_u64(current) {
            Some(v) => v,
            None => return EINVAL,
        };
        if idx >= MAX_THREADS {
            return EINVAL;
        }
        match boxes[idx].reply_target(dest_thread_id) {
            Some(target) => target,
            None => return EACCES,
        }
    };
    if target.endpoint == 0 {
        return EINVAL;
    }
    let target_thread = match resolve_endpoint_handle(target.endpoint) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    let status = send_to_thread_id_with_kind(
        target_thread,
        caller_handle,
        target.call_id,
        buf_ptr,
        len,
        true,
        false,
        FileHandleAttachments::empty(),
    );
    if status == 0 {
        let mut boxes = lock_mailboxes();
        if let Some((idx, _)) = crate::task::thread_slot_index_and_generation_by_u64(current) {
            if idx < MAX_THREADS {
                boxes[idx].remove_reply_target(target);
            }
        }
    }
    status
}

fn recv_blocking_reply_for_thread(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    expected_sender: u64,
    expected_call_id: u64,
    buf_ptr: u64,
    max_len: u64,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    loop {
        let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
        let recv = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_reply_to_user(
                expected_sender,
                expected_call_id,
                receiver_thread_id,
                idx as u16,
                receiver_generation,
                buf_ptr,
                max_copy,
            ) {
                Ok(Some(v)) => Some(v),
                Ok(None) => {
                    boxes[idx].waiter = caller_thread_id;
                    None
                }
                Err(error) => return error,
            }
        };

        match recv {
            Some((from, copy_len)) => {
                return (from << 32) | (copy_len as u64);
            }
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    let second_try = boxes[idx].pop_reply_to_user(
                        expected_sender,
                        expected_call_id,
                        receiver_thread_id,
                        idx as u16,
                        receiver_generation,
                        buf_ptr,
                        max_copy,
                    );
                    if let Ok(Some((from, copy_len))) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        return (from << 32) | (copy_len as u64);
                    }
                    if let Err(error) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        return error;
                    }
                }
                if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(
                    caller_thread_id,
                )) {
                    crate::task::yield_now();
                } else {
                    // The caller's mailbox also carries ordinary events. A wakeup
                    // without a reply must not abort an already-delivered IPC call.
                    let mut boxes = lock_mailboxes();
                    if boxes[idx].waiter == caller_thread_id {
                        boxes[idx].waiter = 0;
                    }
                }
            }
        }
    }
}

pub fn wait(buf_ptr: u64, max_len: u64, blocking: u64) -> u64 {
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(current);
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, None);
    }
    let target_thread = match resolve_endpoint_handle(blocking) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    recv_blocking_for_thread(target_thread, current, buf_ptr, max_len, None)
}

pub fn send_to_endpoint(endpoint: IpcEndpoint, buf_ptr: u64, len: u64) -> u64 {
    if !endpoint_is_valid(endpoint) {
        return EINVAL;
    }
    send(endpoint.thread_id, buf_ptr, len)
}

pub fn send_pages_to_endpoint(
    endpoint: IpcEndpoint,
    map_start: u64,
    total: u64,
    pages: &[u64],
) -> bool {
    if !endpoint_is_valid(endpoint) {
        return false;
    }
    send_pages_from_kernel(endpoint.thread_id, map_start, total, pages)
}

pub fn send_map_header_to_endpoint(endpoint: IpcEndpoint, map_start: u64, total: u64) -> bool {
    if !endpoint_is_valid(endpoint) {
        return false;
    }
    send_map_header_from_kernel(endpoint.thread_id, map_start, total)
}

#[inline]
fn ipc_mailbox_cap() -> usize {
    // At least one ordinary message and one synchronous reply must fit.
    crate::config::kernel()
        .ipc
        .mailbox_cap
        .clamp(2, MAILBOX_CAP)
}

#[inline]
fn ipc_max_msg_size() -> usize {
    crate::config::kernel().ipc.max_msg_size.min(MAX_MSG_SIZE)
}

#[inline]
fn ipc_max_external_pages() -> usize {
    crate::config::kernel()
        .ipc
        .max_external_pages
        .min(MAX_EXT_PAGES)
}

#[inline]
fn record_ipc_copy(bytes: usize) {
    crate::performance::increment(
        crate::performance::CounterMetric::IpcBytesCopied,
        bytes as u64,
    );
}

fn decode_outgoing_file_handles(pointer: u64) -> Result<FileHandleAttachments, u64> {
    if pointer == 0 {
        return Err(EFAULT);
    }
    let mut bytes = [0u8; core::mem::size_of::<mnu_abi::IpcFileHandles>()];
    crate::syscall::copy_from_user(pointer, &mut bytes)?;
    let count = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_| EINVAL)?) as usize;
    let reserved = u32::from_le_bytes(bytes[4..8].try_into().map_err(|_| EINVAL)?);
    if count > MAX_FILE_HANDLES || reserved != 0 {
        return Err(EINVAL);
    }
    let process_id = crate::syscall::security::current_process_id().ok_or(EINVAL)?;
    let mut attachments = FileHandleAttachments::empty();
    for index in 0..count {
        let offset = 8 + index * 8;
        let fd = i32::from_le_bytes(bytes[offset..offset + 4].try_into().map_err(|_| EINVAL)?);
        let rights = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| EINVAL)?,
        );
        if fd < crate::task::FD_BASE as i32 {
            return Err(EBADF);
        }
        let requested = FileHandleCap::from_bits(rights).ok_or(EINVAL)?;
        let duplicated = crate::task::with_process(process_id, |process| {
            let source = process.fd_table().get(fd as usize).ok_or(EBADF)?;
            source
                .duplicate_restricted(requested)
                .map(Box::new)
                .ok_or(EACCES)
        })
        .ok_or(EBADF)??;
        attachments.handles[index] = Some(duplicated);
        attachments.count += 1;
    }
    Ok(attachments)
}

fn install_received_file_handles(
    receiver_thread_id: u64,
    mut attachments: FileHandleAttachments,
    output_pointer: u64,
) -> Result<(), u64> {
    let process_id = crate::task::thread_to_process_id(receiver_thread_id).ok_or(EINVAL)?;
    let mut installed = [0usize; MAX_FILE_HANDLES];
    let mut rights = [0u32; MAX_FILE_HANDLES];
    let count = attachments.count;
    let result = crate::task::with_process_mut(process_id, |process| {
        for index in 0..count {
            let handle = attachments.handles[index].take().ok_or(EINVAL)?;
            rights[index] = handle.cap.bits();
            let Some(fd) = process.fd_table_mut().alloc(handle, true) else {
                for installed_fd in installed[..index].iter().copied() {
                    let _ = process.fd_table_mut().take(installed_fd);
                }
                return Err(ENOSPC);
            };
            installed[index] = fd;
        }
        Ok(())
    })
    .ok_or(EINVAL)?;
    result?;

    let mut output = [0u8; core::mem::size_of::<mnu_abi::IpcFileHandles>()];
    output[0..4].copy_from_slice(&(count as u32).to_le_bytes());
    for index in 0..count {
        let offset = 8 + index * 8;
        output[offset..offset + 4].copy_from_slice(&(installed[index] as i32).to_le_bytes());
        output[offset + 4..offset + 8].copy_from_slice(&rights[index].to_le_bytes());
    }
    if let Err(error) = crate::syscall::copy_to_user(output_pointer, &output) {
        let _ = crate::task::with_process_mut(process_id, |process| {
            for fd in installed[..count].iter().copied() {
                let _ = process.fd_table_mut().take(fd);
            }
        });
        return Err(error);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ExternalPages {
    count: u32,
    total: u64,
    source_page_table: u64,
    source_base: u64,
    inline_pages_count: u16,
    inline_pages: [u64; MAX_INLINE_EXT_PAGES],
}

struct FileHandleAttachments {
    count: usize,
    handles: [Option<Box<FileHandle>>; MAX_FILE_HANDLES],
}

impl FileHandleAttachments {
    const fn empty() -> Self {
        Self {
            count: 0,
            handles: [const { None }; MAX_FILE_HANDLES],
        }
    }

    const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl core::fmt::Debug for FileHandleAttachments {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FileHandleAttachments")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl ExternalPages {
    const fn empty() -> Self {
        Self {
            count: 0,
            total: 0,
            source_page_table: 0,
            source_base: 0,
            inline_pages_count: 0,
            inline_pages: [0; MAX_INLINE_EXT_PAGES],
        }
    }

    const fn is_empty(self) -> bool {
        self.count == 0
    }
}

#[derive(Debug)]
pub struct Message {
    from: u64,
    to: u64,
    to_slot: u16,
    to_generation: u64,
    is_reply: bool,
    expects_reply: bool,
    call_id: u64,
    len: usize,
    data: [u8; MAX_MSG_SIZE],
    ext_pages: ExternalPages,
    file_handles: FileHandleAttachments,
}

impl Message {
    const fn empty() -> Self {
        Self {
            from: 0,
            to: 0,
            to_slot: 0,
            to_generation: 0,
            is_reply: false,
            expects_reply: false,
            call_id: 0,
            len: 0,
            data: [0; MAX_MSG_SIZE],
            ext_pages: ExternalPages::empty(),
            file_handles: FileHandleAttachments::empty(),
        }
    }
}

struct UserReceive {
    from: u64,
    copy_len: usize,
    ext_pages: ExternalPages,
    expects_reply: bool,
    call_id: u64,
    external_header: [u8; 16],
    file_handles: FileHandleAttachments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplyTarget {
    endpoint: u64,
    call_id: u64,
}

#[derive(Debug)]
struct Mailbox {
    head: usize,
    tail: usize,
    count: usize,
    queue: [u8; MAILBOX_CAP],
    slots: [Option<Box<Message>>; MAILBOX_CAP],
    free: [u8; MAILBOX_CAP],
    free_count: usize,
    /// メッセージ待ちでスリープ中のスレッドID (0=なし)
    waiter: u64,
    /// Endpoints whose synchronous calls this thread has received and may
    /// answer later.
    reply_targets: Vec<ReplyTarget>,
}

impl Mailbox {
    const fn new() -> Self {
        let mut free = [0u8; MAILBOX_CAP];
        let mut i = 0;
        while i < MAILBOX_CAP {
            free[i] = i as u8;
            i += 1;
        }
        Self {
            head: 0,
            tail: 0,
            count: 0,
            queue: [0; MAILBOX_CAP],
            slots: [const { None }; MAILBOX_CAP],
            free,
            free_count: MAILBOX_CAP,
            waiter: 0,
            reply_targets: Vec::new(),
        }
    }

    fn add_reply_target(&mut self, endpoint: u64, call_id: u64) {
        let target = ReplyTarget { endpoint, call_id };
        if endpoint != 0 && call_id != 0 && !self.reply_targets.contains(&target) {
            self.reply_targets.push(target);
        }
    }

    fn reply_target(&self, endpoint: u64) -> Option<ReplyTarget> {
        self.reply_targets
            .iter()
            .copied()
            .find(|target| target.endpoint == endpoint)
    }

    fn remove_reply_target(&mut self, target: ReplyTarget) {
        if let Some(index) = self.reply_targets.iter().position(|value| *value == target) {
            self.reply_targets.swap_remove(index);
        }
    }

    fn reserve_slot(&mut self, is_reply: bool) -> Option<usize> {
        // A caller waiting for a reply cannot drain ordinary notifications.
        // Keep one queue slot available for its outstanding synchronous call.
        let limit = ipc_mailbox_cap().saturating_sub(usize::from(!is_reply));
        if self.free_count == 0 || self.count >= limit {
            return None;
        }
        self.free_count -= 1;
        let idx = self.free[self.free_count] as usize;
        if idx >= MAILBOX_CAP || self.slots[idx].is_some() {
            self.quarantine("ipc mailbox free list points to an occupied slot");
            return None;
        }
        Some(idx)
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        let message = allocate_message()?;
        let Some(idx) = self.reserve_slot(false) else {
            release_message(message);
            return None;
        };
        self.slots[idx] = Some(message);
        Some(idx)
    }

    fn enqueue_message(&mut self, message: Box<Message>) -> Result<(), ()> {
        let Some(slot_idx) = self.reserve_slot(message.is_reply) else {
            release_message(message);
            return Err(());
        };
        self.slots[slot_idx] = Some(message);
        if self.enqueue_slot(slot_idx).is_err() {
            let _ = self.free_slot(slot_idx);
            return Err(());
        }
        Ok(())
    }

    fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            release_message(message);
        }
        *self = Self::new();
    }

    fn free_slot(&mut self, idx: usize) -> bool {
        if idx >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: slot index out of range");
            return false;
        }
        if self.free_count >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: free_count overflow");
            return false;
        }
        for i in 0..self.free_count {
            if self.free[i] as usize == idx {
                self.quarantine("ipc mailbox free list corrupted: double free");
                return false;
            }
        }

        let Some(message) = self.slots[idx].take() else {
            self.quarantine("ipc mailbox slot missing during free");
            return false;
        };
        release_message(message);
        self.free[self.free_count] = idx as u8;
        self.free_count += 1;
        true
    }

    fn enqueue_slot(&mut self, slot_idx: usize) -> Result<(), ()> {
        if self.count >= MAILBOX_CAP {
            return Err(());
        }
        self.queue[self.tail] = slot_idx as u8;
        self.tail = (self.tail + 1) % MAILBOX_CAP;
        self.count += 1;
        Ok(())
    }

    fn dequeue_slot(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let idx = self.queue[self.head] as usize;
        self.head = (self.head + 1) % MAILBOX_CAP;
        self.count -= 1;
        Some(idx)
    }

    fn push_message(
        &mut self,
        from: u64,
        to: u64,
        to_slot: u16,
        to_generation: u64,
        data: &[u8],
        is_reply: bool,
        expects_reply: bool,
        call_id: u64,
    ) -> Result<(), ()> {
        if data.len() > ipc_max_msg_size() {
            return Err(());
        }
        let slot_idx = match self.alloc_slot() {
            Some(i) => i,
            None => return Err(()),
        };
        let Some(msg) = self.slots[slot_idx].as_deref_mut() else {
            self.quarantine("ipc mailbox allocated slot is missing");
            return Err(());
        };
        msg.from = from;
        msg.to = to;
        msg.to_slot = to_slot;
        msg.to_generation = to_generation;
        msg.is_reply = is_reply;
        msg.expects_reply = expects_reply;
        msg.call_id = call_id;
        msg.len = data.len();
        msg.ext_pages = ExternalPages::empty();
        msg.file_handles = FileHandleAttachments::empty();
        if !data.is_empty() {
            msg.data[..data.len()].copy_from_slice(data);
            record_ipc_copy(data.len());
        }
        if self.enqueue_slot(slot_idx).is_err() {
            let _ = self.free_slot(slot_idx);
            return Err(());
        }
        Ok(())
    }

    fn pop_valid_for_receiver_to_user(
        &mut self,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        buf_ptr: u64,
        max_copy: usize,
        accept_file_handles: bool,
    ) -> Result<Option<UserReceive>, u64> {
        while self.count > 0 {
            let slot_idx = self.queue[self.head] as usize;
            let Some(msg) = self.slots.get_mut(slot_idx).and_then(Option::as_deref_mut) else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return Ok(None);
            };
            if msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
            {
                let _ = self.dequeue_slot();
                if !self.free_slot(slot_idx) {
                    return Ok(None);
                }
                continue;
            }
            if !accept_file_handles && !msg.file_handles.is_empty() {
                return Err(EMSGSIZE);
            }

            let copy_len = core::cmp::min(msg.len, max_copy);
            let mut external_header = [0u8; 16];
            if msg.ext_pages.is_empty() {
                if copy_len > 0 && buf_ptr != 0 {
                    crate::syscall::copy_to_user(buf_ptr, &msg.data[..copy_len])?;
                    record_ipc_copy(copy_len);
                }
            } else {
                if copy_len < external_header.len() {
                    return Err(EFAULT);
                }
                external_header.copy_from_slice(&msg.data[..16]);
                record_ipc_copy(16);
            }

            let receive = UserReceive {
                from: msg.from,
                copy_len,
                ext_pages: msg.ext_pages,
                expects_reply: msg.expects_reply,
                call_id: msg.call_id,
                external_header,
                file_handles: core::mem::replace(
                    &mut msg.file_handles,
                    FileHandleAttachments::empty(),
                ),
            };
            let dequeued = self.dequeue_slot();
            if dequeued != Some(slot_idx) || !self.free_slot(slot_idx) {
                return Ok(None);
            }
            return Ok(Some(receive));
        }
        Ok(None)
    }

    /// 指定送信元からの有効メッセージを1件だけ取り出し、内容を out へコピーする
    fn pop_from_sender_copy(
        &mut self,
        sender: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        out: &mut [u8],
        reply_only: bool,
    ) -> Option<(u64, usize, bool)> {
        if self.count == 0 {
            return None;
        }

        let original = self.count;
        for _ in 0..original {
            let slot_idx = self.dequeue_slot()?;
            let Some(msg) = self.slots[slot_idx].as_deref() else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return None;
            };
            if msg.from != sender
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || (reply_only && !msg.is_reply)
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return None;
                }
                continue;
            }

            let copy_len = core::cmp::min(msg.len, out.len());
            if copy_len > 0 {
                out[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                record_ipc_copy(copy_len);
            }
            let from = msg.from;
            let expects_reply = msg.expects_reply;
            if !self.free_slot(slot_idx) {
                return None;
            }
            return Some((from, copy_len, expects_reply));
        }

        None
    }

    fn pop_reply_to_user(
        &mut self,
        expected_sender: u64,
        expected_call_id: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        buf_ptr: u64,
        max_copy: usize,
    ) -> Result<Option<(u64, usize)>, u64> {
        if self.count == 0 {
            return Ok(None);
        }

        let original = self.count;
        for _ in 0..original {
            let Some(slot_idx) = self.dequeue_slot() else {
                return Ok(None);
            };
            let Some(msg) = self.slots.get(slot_idx).and_then(Option::as_deref) else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return Ok(None);
            };
            if msg.from != expected_sender
                || msg.call_id != expected_call_id
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || !msg.is_reply
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return Ok(None);
                }
                continue;
            }

            let copy_len = core::cmp::min(msg.len, max_copy);
            if copy_len > 0 && buf_ptr != 0 {
                if let Err(error) = crate::syscall::copy_to_user(buf_ptr, &msg.data[..copy_len]) {
                    if self.enqueue_slot(slot_idx).is_err() {
                        let _ = self.free_slot(slot_idx);
                    }
                    return Err(error);
                }
                record_ipc_copy(copy_len);
            }
            let from = msg.from;
            if !self.free_slot(slot_idx) {
                return Ok(None);
            }
            return Ok(Some((from, copy_len)));
        }

        Ok(None)
    }

    fn pop_reply_copy(
        &mut self,
        expected_sender: u64,
        expected_call_id: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        output: &mut [u8],
    ) -> Option<(u64, usize)> {
        if self.count == 0 {
            return None;
        }
        let original = self.count;
        for _ in 0..original {
            let slot_idx = self.dequeue_slot()?;
            let Some(msg) = self.slots.get(slot_idx).and_then(Option::as_deref) else {
                self.quarantine("ipc mailbox queue points to an empty slot");
                return None;
            };
            if msg.from != expected_sender
                || msg.call_id != expected_call_id
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
                || !msg.is_reply
            {
                if self.enqueue_slot(slot_idx).is_err() {
                    let _ = self.free_slot(slot_idx);
                    return None;
                }
                continue;
            }
            let copy_len = core::cmp::min(msg.len, output.len());
            output[..copy_len].copy_from_slice(&msg.data[..copy_len]);
            let from = msg.from;
            if !self.free_slot(slot_idx) {
                return None;
            }
            record_ipc_copy(copy_len);
            return Some((from, copy_len));
        }
        None
    }

    /// メッセージを積んだ後、待機中スレッドがいれば返して登録を消す
    fn take_waiter(&mut self) -> u64 {
        let w = self.waiter;
        self.waiter = 0;
        w
    }
}

struct MessageCache {
    slots: [Option<Box<Message>>; MESSAGE_CACHE_CAP],
    count: usize,
}

impl MessageCache {
    const fn new() -> Self {
        Self {
            slots: [const { None }; MESSAGE_CACHE_CAP],
            count: 0,
        }
    }

    fn take(&mut self) -> Option<Box<Message>> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        match self.slots[self.count].take() {
            Some(message) => Some(message),
            None => {
                self.quarantine("ipc message cache count points to an empty slot");
                None
            }
        }
    }

    fn put(&mut self, message: Box<Message>) -> Result<(), Box<Message>> {
        if self.count >= MESSAGE_CACHE_CAP {
            return Err(message);
        }
        if self.slots[self.count].is_some() {
            self.quarantine("ipc message cache points to an occupied slot");
            return Err(message);
        }
        self.slots[self.count] = Some(message);
        self.count += 1;
        Ok(())
    }

    fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            drop(wipe_message(message));
        }
        self.count = 0;
    }
}

fn wipe_message(mut message: Box<Message>) -> Box<Message> {
    for handle in &mut message.file_handles.handles {
        drop(handle.take());
    }
    // The volatile replacement keeps message contents from surviving in a
    // reusable kernel heap allocation after the queue releases them.
    unsafe {
        core::ptr::write_volatile(message.as_mut(), Message::empty());
    }
    message
}

fn release_message(message: Box<Message>) {
    let message = wipe_message(message);
    if let Err(message) = MESSAGE_CACHE.lock().put(message) {
        drop(message);
    }
}

fn allocate_message() -> Option<Box<Message>> {
    if let Some(message) = MESSAGE_CACHE.lock().take() {
        return Some(message);
    }
    let layout = Layout::new::<Message>();
    // SAFETY: The returned pointer is checked before it is initialized and
    // converted into a Box with the same global allocator and layout.
    let pointer = unsafe { alloc(layout) }.cast::<Message>();
    if pointer.is_null() {
        return None;
    }
    // SAFETY: `pointer` is non-null, suitably aligned for Message, and owns one
    // allocation of exactly `Layout::new::<Message>()` bytes.
    let message = unsafe {
        pointer.write(Message::empty());
        Box::from_raw(pointer)
    };
    crate::performance::increment(crate::performance::CounterMetric::IpcSendAllocations, 1);
    Some(message)
}

static MESSAGE_CACHE: SpinLock<MessageCache> = SpinLock::new(MessageCache::new());
static MAILBOXES: SpinLock<[Mailbox; MAX_THREADS]> =
    SpinLock::new([const { Mailbox::new() }; MAX_THREADS]);

#[inline]
fn lock_mailboxes() -> SpinLockGuard<'static, [Mailbox; MAX_THREADS]> {
    #[cfg(feature = "performance-instrumentation")]
    let start = crate::performance::timestamp();
    let guard = MAILBOXES.lock();
    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(crate::performance::LatencyMetric::IpcLockWait, start);
    guard
}

/// カーネル内部からIPC送信（ユーザー空間コピー不要）
pub fn send_from_kernel(dest_thread_id: u64, data: &[u8]) -> bool {
    let len = data.len();
    if len > ipc_max_msg_size() {
        return false;
    }
    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return false,
        };
    if idx >= MAX_THREADS {
        return false;
    }
    let sender = crate::task::current_thread_id()
        .and_then(|t| ensure_endpoint_for_thread(t.as_u64()))
        .unwrap_or(0);
    lock_mailboxes().get_mut(idx).map_or(false, |mb| {
        if mb
            .push_message(
                sender,
                dest_thread_id,
                idx as u16,
                dest_generation,
                data,
                false,
                false,
                0,
            )
            .is_ok()
        {
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

/// Performs a synchronous IPC call without copying through userspace buffers.
pub fn call_from_kernel(
    dest_endpoint_handle: u64,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, u64> {
    if request.len() > ipc_max_msg_size() || reply.len() > ipc_max_msg_size() {
        return Err(EINVAL);
    }
    let dest_record = endpoint_record_from_handle(dest_endpoint_handle).ok_or(EINVAL)?;
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return Err(EACCES);
    }
    let caller = crate::task::current_thread_id().ok_or(EINVAL)?.as_u64();
    let sender = ensure_endpoint_for_thread(caller).ok_or(EINVAL)?;
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let (dest_slot, dest_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(dest_record.thread_id)
            .ok_or(EINVAL)?;
    loop {
        let mut mailboxes = lock_mailboxes();
        let mailbox = mailboxes.get_mut(dest_slot).ok_or(EINVAL)?;
        match mailbox.push_message(
            sender,
            dest_record.thread_id,
            dest_slot as u16,
            dest_generation,
            request,
            false,
            true,
            call_id,
        ) {
            Ok(()) => {
                let waiter = mailbox.take_waiter();
                drop(mailboxes);
                if waiter != 0 {
                    crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
                }
                break;
            }
            Err(()) => {
                drop(mailboxes);
                crate::task::yield_now();
            }
        }
    }
    let (caller_slot, caller_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(caller).ok_or(EINVAL)?;
    loop {
        let received = {
            let mut mailboxes = lock_mailboxes();
            let mailbox = mailboxes.get_mut(caller_slot).ok_or(EINVAL)?;
            let received = mailbox.pop_reply_copy(
                dest_endpoint_handle,
                call_id,
                caller,
                caller_slot as u16,
                caller_generation,
                reply,
            );
            if received.is_none() {
                mailbox.waiter = caller;
            }
            received
        };
        if let Some((_, length)) = received {
            return Ok(length);
        }
        if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(caller)) {
            crate::task::yield_now();
        } else {
            let mut mailboxes = lock_mailboxes();
            if mailboxes[caller_slot].waiter == caller {
                mailboxes[caller_slot].waiter = 0;
            }
        }
    }
}

/// Kernel -> recipient: send a message that carries explicit physical page frame addresses.
pub fn send_pages_from_kernel(
    dest_thread_id: u64,
    map_start: u64,
    total: u64,
    pages: &[u64],
) -> bool {
    if pages.len() > MAX_INLINE_EXT_PAGES || pages.len() > ipc_max_external_pages() {
        return false;
    }
    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return false,
        };
    if idx >= MAX_THREADS {
        return false;
    }
    let sender = crate::task::current_thread_id()
        .and_then(|t| ensure_endpoint_for_thread(t.as_u64()))
        .unwrap_or(0);
    let mut boxes = lock_mailboxes();
    boxes.get_mut(idx).map_or(false, |mb| {
        if 16 > ipc_max_msg_size() {
            return false;
        }
        if let Some(slot_idx) = mb.alloc_slot() {
            let Some(msg) = mb.slots[slot_idx].as_deref_mut() else {
                mb.quarantine("ipc mailbox allocated slot is missing");
                return false;
            };
            msg.from = sender;
            msg.to = dest_thread_id;
            msg.to_slot = idx as u16;
            msg.to_generation = dest_generation;
            msg.is_reply = false;
            msg.expects_reply = false;
            // serialize map_start, total only.
            // 物理ページ配列は data に露出させず ext_pages 側だけに保持する。
            msg.data[0..8].copy_from_slice(&map_start.to_le_bytes());
            msg.data[8..16].copy_from_slice(&total.to_le_bytes());
            msg.len = 16;
            msg.ext_pages = ExternalPages::empty();
            msg.ext_pages.count = pages.len() as u32;
            msg.ext_pages.total = total;
            msg.ext_pages.inline_pages_count = pages.len() as u16;
            for (index, page) in pages.iter().enumerate() {
                msg.ext_pages.inline_pages[index] = *page;
            }
            // enqueue
            if mb.enqueue_slot(slot_idx).is_err() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

fn send_virtual_pages_from_kernel(
    dest_thread_id: u64,
    map_start: u64,
    total: u64,
    page_count: usize,
    source_page_table: u64,
    source_base: u64,
) -> bool {
    if page_count == 0 || page_count > ipc_max_external_pages() {
        return false;
    }
    let Ok(count) = u32::try_from(page_count) else {
        return false;
    };
    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return false,
        };
    if idx >= MAX_THREADS {
        return false;
    }
    let sender = crate::task::current_thread_id()
        .and_then(|t| ensure_endpoint_for_thread(t.as_u64()))
        .unwrap_or(0);
    let mut boxes = lock_mailboxes();
    boxes.get_mut(idx).map_or(false, |mb| {
        if 16 > ipc_max_msg_size() {
            return false;
        }
        if let Some(slot_idx) = mb.alloc_slot() {
            let Some(msg) = mb.slots[slot_idx].as_deref_mut() else {
                mb.quarantine("ipc mailbox allocated slot is missing");
                return false;
            };
            msg.from = sender;
            msg.to = dest_thread_id;
            msg.to_slot = idx as u16;
            msg.to_generation = dest_generation;
            msg.is_reply = false;
            msg.expects_reply = false;
            msg.data[0..8].copy_from_slice(&map_start.to_le_bytes());
            msg.data[8..16].copy_from_slice(&total.to_le_bytes());
            msg.len = 16;
            msg.ext_pages = ExternalPages {
                count,
                total,
                source_page_table,
                source_base,
                inline_pages_count: 0,
                inline_pages: [0; MAX_INLINE_EXT_PAGES],
            };
            if mb.enqueue_slot(slot_idx).is_err() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

// New: Kernel -> recipient: send a map header only (magic + map_start + total) without page list
pub fn send_map_header_from_kernel(dest_thread_id: u64, map_start: u64, total: u64) -> bool {
    const MAP_HEADER_MAGIC: u32 = 0xABCD_DCBAu32;
    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return false,
        };
    if idx >= MAX_THREADS {
        return false;
    }
    let sender = crate::task::current_thread_id()
        .map(|t| t.as_u64())
        .unwrap_or(0);
    let mut boxes = lock_mailboxes();
    boxes.get_mut(idx).map_or(false, |mb| {
        if 20 > ipc_max_msg_size() {
            return false;
        }
        if let Some(slot_idx) = mb.alloc_slot() {
            let Some(msg) = mb.slots[slot_idx].as_deref_mut() else {
                mb.quarantine("ipc mailbox allocated slot is missing");
                return false;
            };
            msg.from = sender;
            msg.to = dest_thread_id;
            msg.to_slot = idx as u16;
            msg.to_generation = dest_generation;
            msg.is_reply = false;
            msg.expects_reply = false;
            // New format: [magic:u32][map_start:u64][total:u64] (20 bytes)
            let mut off = 0usize;
            msg.data[off..off + 4].copy_from_slice(&MAP_HEADER_MAGIC.to_le_bytes());
            off += 4;
            msg.data[off..off + 8].copy_from_slice(&map_start.to_le_bytes());
            off += 8;
            msg.data[off..off + 8].copy_from_slice(&(total).to_le_bytes());
            off += 8;
            crate::debug!(
                "[IPC KERN] map_header: magic={:#x} map_start={:#x} total={} len={}",
                MAP_HEADER_MAGIC,
                map_start,
                total,
                off
            );
            crate::info!(
                "[IPC KERN] send_map_header dest={} map_start=0x{:x} total={} len={}",
                dest_thread_id,
                map_start,
                total,
                off
            );
            msg.len = off;
            msg.ext_pages = ExternalPages::empty();
            // enqueue
            if mb.enqueue_slot(slot_idx).is_err() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

fn send_to_thread_id(dest_thread_id: u64, sender_handle: u64, buf_ptr: u64, len: u64) -> u64 {
    send_to_thread_id_with_kind(
        dest_thread_id,
        sender_handle,
        0,
        buf_ptr,
        len,
        false,
        false,
        FileHandleAttachments::empty(),
    )
}

fn send_call_to_thread_id(
    dest_thread_id: u64,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
) -> u64 {
    send_to_thread_id_with_kind(
        dest_thread_id,
        sender_handle,
        call_id,
        buf_ptr,
        len,
        false,
        true,
        FileHandleAttachments::empty(),
    )
}

fn send_to_thread_id_with_kind(
    dest_thread_id: u64,
    sender_handle: u64,
    call_id: u64,
    buf_ptr: u64,
    len: u64,
    is_reply: bool,
    expects_reply: bool,
    file_handles: FileHandleAttachments,
) -> u64 {
    if dest_thread_id == 0 {
        return EINVAL;
    }

    let len = len as usize;
    if len > ipc_max_msg_size() {
        return EINVAL;
    }
    if len > 0 && buf_ptr == 0 {
        return EFAULT;
    }

    let (idx, dest_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(dest_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    #[cfg(feature = "performance-instrumentation")]
    let send_start = crate::performance::timestamp();

    // NOTE:
    // - 宛先スロットに加えて世代番号をメッセージへ埋め込む。
    // - これにより、送信先終了後に同一スロットへ別スレッドが再利用されても誤配送されない。
    // - 送信時点と受信時点で世代不一致なら古いメッセージとして破棄される。

    let Some(mut message) = allocate_message() else {
        return EAGAIN;
    };
    message.from = sender_handle;
    message.to = dest_thread_id;
    message.to_slot = idx as u16;
    message.to_generation = dest_generation;
    message.is_reply = is_reply;
    message.expects_reply = expects_reply;
    message.call_id = call_id;
    message.len = len;
    message.ext_pages = ExternalPages::empty();
    message.file_handles = file_handles;

    // ユーザー空間から、キューが所有する領域へ直接コピーする。
    if len > 0 && buf_ptr != 0 {
        if let Err(err) = crate::syscall::copy_from_user(buf_ptr, &mut message.data[..len]) {
            release_message(message);
            return err;
        }
        record_ipc_copy(len);
    }
    let mut boxes = lock_mailboxes();
    if boxes[idx].enqueue_message(message).is_err() {
        return EAGAIN;
    }
    crate::debug!(
        "[IPC SEND] from={} to={} len={}",
        sender_handle,
        dest_thread_id,
        len
    );
    let waiter = boxes[idx].take_waiter();
    drop(boxes);
    if waiter != 0 {
        crate::task::wake_ipc_waiter(crate::task::ThreadId::from_u64(waiter));
    }

    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(
        if len >= 4096 {
            crate::performance::LatencyMetric::IpcFourKilobytes
        } else {
            crate::performance::LatencyMetric::IpcSmallOneWay
        },
        send_start,
    );

    0
}

/// IPC送信
/// arg0: endpoint handle
/// arg1: buf_ptr
/// arg2: len
pub fn send(dest_endpoint_handle: u64, buf_ptr: u64, len: u64) -> u64 {
    let dest_record = match endpoint_record_from_handle(dest_endpoint_handle) {
        Some(record) => record,
        None => return EINVAL,
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return EACCES;
    }
    let dest_thread_id = dest_record.thread_id;
    let sender = match crate::task::current_thread_id() {
        Some(id) => ensure_endpoint_for_thread(id.as_u64()).unwrap_or(EINVAL),
        None => return EINVAL,
    };
    if sender == EINVAL {
        return EINVAL;
    }
    if let Some(sender_record) = endpoint_record_from_handle(sender) {
        if !sender_record.rights.contains(EndpointRights::SEND) {
            return EACCES;
        }
    }

    // capability 強制:
    // IPC で任意スレッドへメッセージを送れると、サービス制御や情報取得が無権限で可能になる。
    // そのため、送信は `ipc.client` または `ipc.server` を持つプロセスに限定する。
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    send_to_thread_id(dest_thread_id, sender, buf_ptr, len)
}

/// Sends one IPC message with explicitly attached, rights-restricted file handles.
pub fn send_handles(dest_endpoint_handle: u64, buf_ptr: u64, len: u64, handles_ptr: u64) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let Some(dest_record) = endpoint_record_from_handle(dest_endpoint_handle) else {
        return EINVAL;
    };
    if !dest_record.rights.contains(EndpointRights::RECV) {
        return EACCES;
    }
    let sender = match crate::task::current_thread_id() {
        Some(id) => match ensure_endpoint_for_thread(id.as_u64()) {
            Some(handle) => handle,
            None => return EINVAL,
        },
        None => return EINVAL,
    };
    if let Some(sender_record) = endpoint_record_from_handle(sender) {
        if !sender_record.rights.contains(EndpointRights::SEND) {
            return EACCES;
        }
    }
    let file_handles = match decode_outgoing_file_handles(handles_ptr) {
        Ok(handles) => handles,
        Err(error) => return error,
    };
    send_to_thread_id_with_kind(
        dest_record.thread_id,
        sender,
        0,
        buf_ptr,
        len,
        false,
        false,
        file_handles,
    )
}

pub fn send_pages(
    dest_endpoint_handle: u64,
    phys_pages_ptr: u64,
    page_count_raw: u64,
    local_base: u64,
) -> u64 {
    if !crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
        crate::capability::Capability::IpcServer,
    ]) {
        return EACCES;
    }
    let dest_thread_id =
        if crate::task::thread_slot_index_and_generation_by_u64(dest_endpoint_handle).is_some() {
            dest_endpoint_handle
        } else {
            match endpoint_record_from_handle(dest_endpoint_handle) {
                Some(record) => {
                    if !record.rights.contains(EndpointRights::RECV) {
                        return EACCES;
                    }
                    record.thread_id
                }
                None => return EINVAL,
            }
        };
    if page_count_raw == 0 || page_count_raw as usize > ipc_max_external_pages() {
        return EINVAL;
    }
    let Ok(page_count) = usize::try_from(page_count_raw) else {
        return EINVAL;
    };
    let total = match page_count_raw.checked_mul(4096) {
        Some(v) => v,
        None => return EINVAL,
    };
    if phys_pages_ptr == 0 {
        if (local_base & 0xfff) != 0 {
            return EINVAL;
        }
        let source_page_table = match crate::syscall::security::current_process_id()
            .and_then(|pid| crate::task::with_process(pid, |process| process.page_table()))
            .flatten()
        {
            Some(pt) => pt,
            None => return EFAULT,
        };
        if send_virtual_pages_from_kernel(
            dest_thread_id,
            local_base,
            total,
            page_count,
            source_page_table,
            local_base,
        ) {
            return 0;
        }
        return EAGAIN;
    } else {
        if page_count > MAX_INLINE_EXT_PAGES {
            return EINVAL;
        }
        let mut pages = [0u64; MAX_INLINE_EXT_PAGES];
        let bytes_len = match page_count_raw.checked_mul(8) {
            Some(v) => v,
            None => return EINVAL,
        };
        if !crate::syscall::validate_user_ptr(phys_pages_ptr, bytes_len) {
            return EFAULT;
        }
        let pages_bytes = unsafe {
            core::slice::from_raw_parts_mut(pages.as_mut_ptr().cast::<u8>(), page_count * 8)
        };
        if let Err(errno) = crate::syscall::copy_from_user(phys_pages_ptr, pages_bytes) {
            return errno;
        }
        if send_pages_from_kernel(dest_thread_id, local_base, total, &pages[..page_count]) {
            0
        } else {
            EAGAIN
        }
    }
}

fn map_external_pages_for_receiver(
    receiver_tid: u64,
    map_start_hint: u64,
    total: u64,
    ext_pages: ExternalPages,
) -> Result<ExternalPageMapping, u64> {
    if ext_pages.count == 0 || ext_pages.count as usize > ipc_max_external_pages() {
        return Err(EINVAL);
    }
    if ext_pages.source_page_table == 0
        && (ext_pages.inline_pages_count == 0
            || ext_pages.inline_pages_count as u32 != ext_pages.count
            || ext_pages.inline_pages_count as usize > MAX_INLINE_EXT_PAGES)
    {
        return Err(EINVAL);
    }
    if total == 0 {
        return Err(EINVAL);
    }
    if ext_pages.total != 0 && total > ext_pages.total {
        return Err(EINVAL);
    }
    let max_bytes = (ext_pages.count as u64).saturating_mul(0x1000);
    if total > max_bytes {
        return Err(EINVAL);
    }

    let target_pid = crate::task::thread_to_process_id(receiver_tid).ok_or(EINVAL)?;
    let page_span = (ext_pages.count as u64).saturating_mul(0x1000);

    let _ = map_start_hint; // 受信側の安全のためヒントは無視して自動配置する
    let (virt_addr, page_table, reserved_mapping_old, reserved_mapping_new) =
        match crate::task::with_process_mut(target_pid, |p| {
            let base = if p.ipc_mapping_end() < 0x7100_0000_0000u64 {
                0x7100_0000_0000u64
            } else {
                p.ipc_mapping_end()
            };
            let virt_addr = base
                .checked_add(0xfff)
                .map(|v| v & !0xfffu64)
                .ok_or(EINVAL)?;
            let new_end = virt_addr.checked_add(page_span).ok_or(EINVAL)?;
            let pt = p.page_table().ok_or(EINVAL)?;
            let old_end = p.ipc_mapping_end();
            p.set_ipc_mapping_end(new_end);
            Ok((virt_addr, pt, old_end, new_end))
        }) {
            Some(Ok(v)) => (v.0, v.1, Some(v.2), Some(v.3)),
            Some(Err(e)) => return Err(e),
            None => return Err(EINVAL),
        };

    for i in 0..(ext_pages.count as usize) {
        let target_virt = virt_addr + (i as u64 * 0x1000);
        let phys_addr = if ext_pages.source_page_table != 0 {
            let Some(source_virt) = ext_pages.source_base.checked_add((i as u64) * 0x1000) else {
                return Err(EINVAL);
            };
            match crate::mem::paging::virt_to_phys_in_table(
                ext_pages.source_page_table,
                source_virt,
            ) {
                Some(phys) => phys & !0xfffu64,
                None => return Err(EFAULT),
            }
        } else {
            ext_pages.inline_pages[i]
        };
        if crate::mem::paging::map_page_in_table(page_table, target_virt, phys_addr, true, true)
            .is_err()
        {
            for j in 0..i {
                let rollback_virt = virt_addr + (j as u64 * 0x1000);
                let _ = crate::mem::paging::unmap_page_in_table(page_table, rollback_virt);
            }
            if let (Some(old_end), Some(new_end)) = (reserved_mapping_old, reserved_mapping_new) {
                let _ = crate::task::with_process_mut(target_pid, |p| {
                    if p.ipc_mapping_end() == new_end {
                        p.set_ipc_mapping_end(old_end);
                    }
                });
            }
            return Err(EFAULT);
        }
    }

    Ok(ExternalPageMapping {
        target_pid,
        page_table,
        virt_addr,
        old_end: reserved_mapping_old.unwrap_or(0),
        new_end: reserved_mapping_new.unwrap_or(0),
        page_count: ext_pages.count as usize,
    })
}

struct ExternalPageMapping {
    target_pid: crate::task::ProcessId,
    page_table: u64,
    virt_addr: u64,
    old_end: u64,
    new_end: u64,
    page_count: usize,
}

impl ExternalPageMapping {
    fn rollback(&self) {
        for i in 0..self.page_count {
            let rollback_virt = self.virt_addr + (i as u64 * 0x1000);
            let _ = crate::mem::paging::unmap_page_in_table(self.page_table, rollback_virt);
        }
        let _ = crate::task::with_process_mut(self.target_pid, |p| {
            if p.ipc_mapping_end() == self.new_end {
                p.set_ipc_mapping_end(self.old_end);
            }
        });
    }
}

fn prepare_external_pages_for_user(
    receiver_tid: u64,
    recv_buf: &mut [u8],
    copy_len: usize,
    ext_pages: ExternalPages,
) -> Result<(usize, Option<ExternalPageMapping>), u64> {
    if ext_pages.is_empty() {
        return Ok((copy_len, None));
    }
    crate::debug!(
        "[IPC RCV] prepare_external_pages_for_user receiver={} copy_len={} ext_pages_count={}",
        receiver_tid,
        copy_len,
        ext_pages.count
    );
    if copy_len < 16 || recv_buf.len() < 16 {
        return Err(EFAULT);
    }
    let map_start_hint = u64::from_le_bytes([
        recv_buf[0],
        recv_buf[1],
        recv_buf[2],
        recv_buf[3],
        recv_buf[4],
        recv_buf[5],
        recv_buf[6],
        recv_buf[7],
    ]);
    let total = u64::from_le_bytes([
        recv_buf[8],
        recv_buf[9],
        recv_buf[10],
        recv_buf[11],
        recv_buf[12],
        recv_buf[13],
        recv_buf[14],
        recv_buf[15],
    ]);
    let mapped_addr =
        map_external_pages_for_receiver(receiver_tid, map_start_hint, total, ext_pages)?;
    recv_buf[0..8].copy_from_slice(&mapped_addr.virt_addr.to_le_bytes());
    recv_buf[8..16].copy_from_slice(&total.to_le_bytes());
    Ok((16, Some(mapped_addr)))
}

fn finish_user_receive(
    receiver_thread_id: u64,
    buf_ptr: u64,
    mut receive: UserReceive,
    file_handles_output: Option<u64>,
) -> Result<(u64, usize, bool), u64> {
    if let Some(output) = file_handles_output {
        install_received_file_handles(receiver_thread_id, receive.file_handles, output)?;
    } else if !receive.file_handles.is_empty() {
        return Err(EMSGSIZE);
    }
    if receive.ext_pages.is_empty() {
        return Ok((receive.from, receive.copy_len, receive.expects_reply));
    }

    let (copy_len, mapping) = prepare_external_pages_for_user(
        receiver_thread_id,
        &mut receive.external_header,
        receive.copy_len,
        receive.ext_pages,
    )?;
    if copy_len > 0 && buf_ptr != 0 {
        if let Err(error) =
            crate::syscall::copy_to_user(buf_ptr, &receive.external_header[..copy_len])
        {
            if let Some(mapping) = mapping.as_ref() {
                mapping.rollback();
            }
            return Err(error);
        }
        record_ipc_copy(copy_len);
    }
    Ok((receive.from, copy_len, receive.expects_reply))
}

fn recv_from_thread_nonblocking(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    buf_ptr: u64,
    max_len: u64,
    file_handles_output: Option<u64>,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
    let receive = {
        let mut boxes = lock_mailboxes();
        match boxes[idx].pop_valid_for_receiver_to_user(
            receiver_thread_id,
            idx as u16,
            receiver_generation,
            buf_ptr,
            max_copy,
            file_handles_output.is_some(),
        ) {
            Ok(Some(receive)) => {
                if let Some((caller_idx, _)) =
                    crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                {
                    if caller_idx < MAX_THREADS && receive.expects_reply {
                        boxes[caller_idx].add_reply_target(receive.from, receive.call_id);
                    }
                }
                receive
            }
            Ok(None) => return EAGAIN,
            Err(error) => return error,
        }
    };
    let (from, copy_len, _) =
        match finish_user_receive(receiver_thread_id, buf_ptr, receive, file_handles_output) {
            Ok(result) => result,
            Err(error) => return error,
        };
    crate::debug!(
        "[IPC RECV] tid={} from={} len={}",
        receiver_thread_id,
        from,
        copy_len
    );

    (from << 32) | (copy_len as u64)
}

fn recv_blocking_for_thread(
    receiver_thread_id: u64,
    caller_thread_id: u64,
    buf_ptr: u64,
    max_len: u64,
    file_handles_output: Option<u64>,
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    loop {
        let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
        let recv = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_valid_for_receiver_to_user(
                receiver_thread_id,
                idx as u16,
                receiver_generation,
                buf_ptr,
                max_copy,
                file_handles_output.is_some(),
            ) {
                Ok(Some(receive)) => {
                    if let Some((caller_idx, _)) =
                        crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                    {
                        if caller_idx < MAX_THREADS && receive.expects_reply {
                            boxes[caller_idx].add_reply_target(receive.from, receive.call_id);
                        }
                    }
                    Some(receive)
                }
                Ok(None) => {
                    boxes[idx].waiter = caller_thread_id;
                    None
                }
                Err(error) => return error,
            }
        };

        match recv {
            Some(receive) => {
                let (from, copy_len, _) = match finish_user_receive(
                    receiver_thread_id,
                    buf_ptr,
                    receive,
                    file_handles_output,
                ) {
                    Ok(result) => result,
                    Err(error) => return error,
                };
                crate::debug!(
                    "[IPC RECV] tid={} from={} len={}",
                    receiver_thread_id,
                    from,
                    copy_len
                );
                return (from << 32) | (copy_len as u64);
            }
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    let second_try = boxes[idx].pop_valid_for_receiver_to_user(
                        receiver_thread_id,
                        idx as u16,
                        receiver_generation,
                        buf_ptr,
                        max_copy,
                        file_handles_output.is_some(),
                    );
                    if let Ok(Some(receive)) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        if let Some((caller_idx, _)) =
                            crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                        {
                            if caller_idx < MAX_THREADS && receive.expects_reply {
                                boxes[caller_idx].add_reply_target(receive.from, receive.call_id);
                            }
                        }
                        drop(boxes);
                        let (from, copy_len, _) = match finish_user_receive(
                            receiver_thread_id,
                            buf_ptr,
                            receive,
                            file_handles_output,
                        ) {
                            Ok(result) => result,
                            Err(error) => return error,
                        };
                        crate::debug!(
                            "[IPC RECV] tid={} from={} len={}",
                            receiver_thread_id,
                            from,
                            copy_len
                        );
                        return (from << 32) | (copy_len as u64);
                    }
                    if let Err(error) = second_try {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        return error;
                    }
                }
                if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(
                    caller_thread_id,
                )) {
                    crate::task::yield_now();
                } else {
                    {
                        let mut boxes = lock_mailboxes();
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                    }
                    // A message or another wakeup raced with the transition to sleep.
                    // Retry the queue before registering a new waiter; a blocking receive
                    // must not surface that internal race as an empty result.
                    continue;
                }
            }
        }
    }
}

/// IPC受信
/// arg0: buf_ptr
/// arg1: len
/// 戻り値: (sender_id << 32) | received_len
pub fn recv(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(receiver);
    if let Some(receiver_handle) = endpoint_handle_for_thread(receiver) {
        if let Some(record) = endpoint_record_from_handle(receiver_handle) {
            if !record.rights.contains(EndpointRights::RECV) {
                return EACCES;
            }
        }
    }
    recv_from_thread_nonblocking(receiver, receiver, buf_ptr, max_len, None)
}

/// IPC受信（ブロッキング版）
/// メッセージが届くまでスレッドをスリープして待機する。
/// arg0: buf_ptr
/// arg1: len
pub fn recv_blocking(buf_ptr: u64, max_len: u64) -> u64 {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(receiver);
    if let Some(receiver_handle) = endpoint_handle_for_thread(receiver) {
        if let Some(record) = endpoint_record_from_handle(receiver_handle) {
            if !record.rights.contains(EndpointRights::RECV) {
                return EACCES;
            }
        }
    }
    recv_blocking_for_thread(receiver, receiver, buf_ptr, max_len, None)
}

/// Receives a message and installs any attached file handles in this process.
///
/// `blocking` follows `ipc_wait`: zero performs a non-blocking receive; a
/// non-zero endpoint selects the receiving thread and waits for a message.
pub fn recv_handles(buf_ptr: u64, max_len: u64, handles_ptr: u64, blocking: u64) -> u64 {
    if handles_ptr == 0 {
        return EFAULT;
    }
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(current);
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len, Some(handles_ptr));
    }
    let target_thread = match resolve_endpoint_handle(blocking) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    recv_blocking_for_thread(target_thread, current, buf_ptr, max_len, Some(handles_ptr))
}

/// カーネル内部から、特定送信元のIPCをノンブロッキング受信する
///
/// - メッセージが無い場合は `Ok(None)`
/// - 受信データは `buf` にコピーされる
pub fn recv_from_sender_for_kernel_nonblocking(
    sender_thread_id: u64,
    buf: &mut [u8],
) -> Result<Option<usize>, u64> {
    let receiver = crate::task::current_thread_id().ok_or(EINVAL)?;
    let receiver_u64 = receiver.as_u64();
    let (idx, receiver_generation) =
        crate::task::thread_slot_index_and_generation_by_u64(receiver_u64).ok_or(EINVAL)?;

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return Err(EINVAL);
    }

    let n = {
        let mut boxes = lock_mailboxes();
        boxes[idx]
            .pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
                false,
            )
            .map(|(_, n, _)| n)
    };

    Ok(n)
}

/// カーネル内部から、特定送信元のIPCをブロッキング受信する
///
/// - 受信データは `buf` へコピーされる（ユーザー空間検証は行わない）
/// - 指定送信元以外のメッセージはキューに保持されたまま
pub fn recv_blocking_from_sender_for_kernel(
    sender_thread_id: u64,
    buf: &mut [u8],
) -> Result<usize, u64> {
    let receiver = match crate::task::current_thread_id() {
        Some(id) => id,
        None => return Err(EINVAL),
    };
    let receiver_u64 = receiver.as_u64();

    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_u64) {
            Some(v) => v,
            None => return Err(EINVAL),
        };
    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return Err(EINVAL);
    }

    loop {
        let n = {
            let mut boxes = lock_mailboxes();
            match boxes[idx].pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
                false,
            ) {
                Some((_, n, _)) => Some(n),
                None => {
                    boxes[idx].waiter = receiver_u64;
                    None
                }
            }
        };

        match n {
            Some(n) => return Ok(n),
            None => {
                {
                    let mut boxes = lock_mailboxes();
                    if let Some((_, n, _)) = boxes[idx].pop_from_sender_copy(
                        sender_thread_id,
                        receiver_u64,
                        idx as u16,
                        receiver_generation,
                        buf,
                        false,
                    ) {
                        if boxes[idx].waiter == receiver_u64 {
                            boxes[idx].waiter = 0;
                        }
                        return Ok(n);
                    }
                }
                if crate::task::sleep_thread_unless_woken(receiver) {
                    crate::task::yield_now();
                } else {
                    let mut boxes = lock_mailboxes();
                    if boxes[idx].waiter == receiver_u64 {
                        boxes[idx].waiter = 0;
                    }
                    return Err(EAGAIN);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use super::{FileHandleAttachments, Mailbox, Message, ReplyTarget};
    use crate::task::FileHandle;

    #[test]
    fn legacy_receive_does_not_consume_attached_handles() {
        let mut mailbox = Mailbox::new();
        let mut message = Box::new(Message::empty());
        message.from = 10;
        message.to = 20;
        message.to_slot = 1;
        message.to_generation = 2;
        message.file_handles = FileHandleAttachments::empty();
        message.file_handles.count = 1;
        message.file_handles.handles[0] = Some(Box::new(FileHandle::new_pipe_read(usize::MAX)));
        mailbox.enqueue_message(message).unwrap();

        assert!(matches!(
            mailbox.pop_valid_for_receiver_to_user(20, 1, 2, 0, 0, false),
            Err(error) if error == mnu_abi::EMSGSIZE
        ));
        assert_eq!(mailbox.count, 1);

        let received = mailbox
            .pop_valid_for_receiver_to_user(20, 1, 2, 0, 0, true)
            .unwrap()
            .expect("attached message should remain queued");
        assert_eq!(received.file_handles.count, 1);
        assert_eq!(mailbox.count, 0);
    }

    #[test]
    fn mailbox_tracks_more_than_one_deferred_reply() {
        let mut mailbox = Mailbox::new();
        mailbox.add_reply_target(11, 101);
        mailbox.add_reply_target(22, 202);
        mailbox.add_reply_target(11, 101);

        assert_eq!(mailbox.reply_target(11).unwrap().call_id, 101);
        assert_eq!(mailbox.reply_target(22).unwrap().call_id, 202);
        assert_eq!(mailbox.reply_targets.len(), 2);

        mailbox.remove_reply_target(ReplyTarget {
            endpoint: 22,
            call_id: 202,
        });
        assert!(mailbox.reply_target(11).is_some());
        assert!(mailbox.reply_target(22).is_none());
    }

    #[test]
    fn synchronous_call_only_consumes_its_servers_reply() {
        let mut mailbox = Mailbox::new();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 100)
            .unwrap();
        mailbox
            .push_message(11, 20, 1, 2, &[], true, false, 200)
            .unwrap();

        assert_eq!(
            mailbox.pop_reply_to_user(11, 200, 20, 1, 2, 0, 0),
            Ok(Some((11, 0)))
        );
        assert_eq!(
            mailbox.pop_reply_to_user(10, 100, 20, 1, 2, 0, 0),
            Ok(Some((10, 0)))
        );
    }

    #[test]
    fn synchronous_call_keeps_stale_reply_from_the_same_server_queued() {
        let mut mailbox = Mailbox::new();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 100)
            .unwrap();
        mailbox
            .push_message(10, 20, 1, 2, &[], true, false, 101)
            .unwrap();

        assert_eq!(
            mailbox.pop_reply_to_user(10, 101, 20, 1, 2, 0, 0),
            Ok(Some((10, 0)))
        );
        assert_eq!(
            mailbox.pop_reply_to_user(10, 100, 20, 1, 2, 0, 0),
            Ok(Some((10, 0)))
        );
    }
}
