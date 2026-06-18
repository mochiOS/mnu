use crate::interrupt::spinlock::SpinLock;
use alloc::collections::BTreeMap;
use alloc::vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::{EACCES, EAGAIN, EFAULT, EINVAL};

const MAX_THREADS: usize = crate::task::ThreadQueue::MAX_THREADS;
const MAILBOX_CAP: usize = 64;
const MAX_MSG_SIZE: usize = 4128; // FsResponse(4112) / DiskBulkResponse(2064) を収容
const MAX_EXT_PAGES: usize = 128;

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

static NEXT_ENDPOINT_HANDLE: AtomicU64 = AtomicU64::new(1);
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

pub fn endpoint_rights_for_process(_process_id: u64) -> EndpointRights {
    let mut rights = EndpointRights::empty();
    if crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcClient,
    ]) {
        rights = rights.union(EndpointRights::SEND);
    }
    if crate::syscall::security::caller_has_any_capability(&[
        crate::capability::Capability::IpcServer,
    ]) {
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
    dest_thread_id: u64,
    req_ptr: u64,
    req_len: u64,
    reply_ptr: u64,
    reply_len: u64,
) -> u64 {
    let sent = send(dest_thread_id, req_ptr, req_len);
    if sent != 0 {
        return sent;
    }
    let caller = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    if ensure_endpoint_for_thread(caller).is_none() {
        return EINVAL;
    }
    recv_blocking_for_thread(caller, caller, reply_ptr, reply_len)
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
    let target_handle = {
        let mut boxes = MAILBOXES.lock();
        let (idx, _) = match crate::task::thread_slot_index_and_generation_by_u64(current) {
            Some(v) => v,
            None => return EINVAL,
        };
        if idx >= MAX_THREADS {
            return EINVAL;
        }
        let pending = boxes[idx].reply_to;
        if pending == 0 || pending != dest_thread_id {
            return EACCES;
        }
        boxes[idx].reply_to = 0;
        pending
    };
    if target_handle == 0 {
        return EINVAL;
    }
    let target_thread = match resolve_endpoint_handle(target_handle) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    let _ = caller_handle;
    send_to_thread_id(target_thread, caller_handle, buf_ptr, len)
}

pub fn wait(buf_ptr: u64, max_len: u64, blocking: u64) -> u64 {
    let current = match crate::task::current_thread_id() {
        Some(id) => id.as_u64(),
        None => return EINVAL,
    };
    let _ = ensure_endpoint_for_thread(current);
    if blocking == 0 {
        return recv_from_thread_nonblocking(current, current, buf_ptr, max_len);
    }
    let target_thread = match resolve_endpoint_handle(blocking) {
        Some(thread_id) => thread_id,
        None => return EINVAL,
    };
    recv_blocking_for_thread(target_thread, current, buf_ptr, max_len)
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
    crate::config::kernel().ipc.mailbox_cap.min(MAILBOX_CAP)
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

#[derive(Debug, Clone, Copy)]
pub struct Message {
    from: u64,
    to: u64,
    to_slot: u16,
    to_generation: u64,
    len: usize,
    data: [u8; MAX_MSG_SIZE],
    ext_pages_count: u16,
    ext_pages: [u64; MAX_EXT_PAGES],
}

impl Message {
    const fn empty() -> Self {
        Self {
            from: 0,
            to: 0,
            to_slot: 0,
            to_generation: 0,
            len: 0,
            data: [0; MAX_MSG_SIZE],
            ext_pages_count: 0,
            ext_pages: [0; MAX_EXT_PAGES],
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Mailbox {
    head: usize,
    tail: usize,
    count: usize,
    queue: [u8; MAILBOX_CAP],
    slots: [Message; MAILBOX_CAP],
    free: [u8; MAILBOX_CAP],
    free_count: usize,
    /// メッセージ待ちでスリープ中のスレッドID (0=なし)
    waiter: u64,
    reply_to: u64,
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
            slots: [Message::empty(); MAILBOX_CAP],
            free,
            free_count: MAILBOX_CAP,
            waiter: 0,
            reply_to: 0,
        }
    }

    fn alloc_slot(&mut self) -> Option<usize> {
        if self.free_count == 0 || self.count >= ipc_mailbox_cap() {
            return None;
        }
        self.free_count -= 1;
        Some(self.free[self.free_count] as usize)
    }

    fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
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

        self.slots[idx] = Message::empty();
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
    ) -> Result<(), ()> {
        if data.len() > ipc_max_msg_size() {
            return Err(());
        }
        let slot_idx = match self.alloc_slot() {
            Some(i) => i,
            None => return Err(()),
        };
        let msg = &mut self.slots[slot_idx];
        msg.from = from;
        msg.to = to;
        msg.to_slot = to_slot;
        msg.to_generation = to_generation;
        msg.len = data.len();
        msg.ext_pages_count = 0;
        if !data.is_empty() {
            msg.data[..data.len()].copy_from_slice(data);
        }
        if self.enqueue_slot(slot_idx).is_err() {
            let _ = self.free_slot(slot_idx);
            return Err(());
        }
        Ok(())
    }

    fn pop_valid_for_receiver_copy(
        &mut self,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        out: &mut [u8],
    ) -> Option<(u64, usize, u16, [u64; MAX_EXT_PAGES])> {
        while let Some(slot_idx) = self.dequeue_slot() {
            let msg = &self.slots[slot_idx];
            if msg.to == receiver
                && msg.to_slot == receiver_slot
                && msg.to_generation == receiver_generation
            {
                let copy_len = core::cmp::min(msg.len, out.len());
                if msg.ext_pages_count > 0 && msg.len == 0 {
                    let from = msg.from;
                    let ext_pages_count = msg.ext_pages_count;
                    let ext_pages = msg.ext_pages;
                    if !self.free_slot(slot_idx) {
                        return None;
                    }
                    return Some((from, 0usize, ext_pages_count, ext_pages));
                }
                if copy_len > 0 {
                    out[..copy_len].copy_from_slice(&msg.data[..copy_len]);
                }
                let from = msg.from;
                let ext_pages_count = msg.ext_pages_count;
                let ext_pages = msg.ext_pages;
                if !self.free_slot(slot_idx) {
                    return None;
                }
                return Some((from, copy_len, ext_pages_count, ext_pages));
            }
            // 古い宛先のメッセージは破棄
            if !self.free_slot(slot_idx) {
                return None;
            }
        }
        None
    }

    /// 指定送信元からの有効メッセージを1件だけ取り出し、内容を out へコピーする
    fn pop_from_sender_copy(
        &mut self,
        sender: u64,
        receiver: u64,
        receiver_slot: u16,
        receiver_generation: u64,
        out: &mut [u8],
    ) -> Option<(u64, usize)> {
        if self.count == 0 {
            return None;
        }

        let original = self.count;
        for _ in 0..original {
            let slot_idx = self.dequeue_slot()?;
            let msg = &self.slots[slot_idx];
            if msg.from != sender
                || msg.to != receiver
                || msg.to_slot != receiver_slot
                || msg.to_generation != receiver_generation
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
            }
            let from = msg.from;
            if !self.free_slot(slot_idx) {
                return None;
            }
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

static MAILBOXES: SpinLock<[Mailbox; MAX_THREADS]> = SpinLock::new([Mailbox::new(); MAX_THREADS]);

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
    MAILBOXES.lock().get_mut(idx).map_or(false, |mb| {
        if mb
            .push_message(sender, dest_thread_id, idx as u16, dest_generation, data)
            .is_ok()
        {
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_thread(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

/// Kernel -> recipient: send a message that carries physical page frame addresses
/// Pages are explicit physical frame addresses (one per 4KiB page). Up to 128 entries supported.
pub fn send_pages_from_kernel(
    dest_thread_id: u64,
    map_start: u64,
    total: u64,
    pages: &[u64],
) -> bool {
    // Keep original behaviour as fallback: send explicit page list when provided.
    // This function will continue to work for up to 128 pages.

    if pages.len() > ipc_max_external_pages() {
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
    let mut boxes = MAILBOXES.lock();
    boxes.get_mut(idx).map_or(false, |mb| {
        if let Some(slot_idx) = mb.alloc_slot() {
            let msg = &mut mb.slots[slot_idx];
            msg.from = sender;
            msg.to = dest_thread_id;
            msg.to_slot = idx as u16;
            msg.to_generation = dest_generation;
            // serialize map_start, total only.
            // 物理ページ配列は data に露出させず ext_pages 側だけに保持する。
            let mut off = 0usize;
            if 16 > ipc_max_msg_size() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            msg.data[off..off + 8].copy_from_slice(&map_start.to_le_bytes());
            off += 8;
            msg.data[off..off + 8].copy_from_slice(&(total).to_le_bytes());
            off += 8;
            msg.len = off;
            msg.ext_pages_count = pages.len() as u16;
            for i in 0..pages.len() {
                msg.ext_pages[i] = pages[i];
            }
            // enqueue
            if mb.enqueue_slot(slot_idx).is_err() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_thread(crate::task::ThreadId::from_u64(waiter));
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
    let mut boxes = MAILBOXES.lock();
    boxes.get_mut(idx).map_or(false, |mb| {
        if let Some(slot_idx) = mb.alloc_slot() {
            let msg = &mut mb.slots[slot_idx];
            msg.from = sender;
            msg.to = dest_thread_id;
            msg.to_slot = idx as u16;
            msg.to_generation = dest_generation;
            // New format: [magic:u32][map_start:u64][total:u64] (20 bytes)
            let mut off = 0usize;
            if 20 > ipc_max_msg_size() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
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
            msg.ext_pages_count = 0;
            // enqueue
            if mb.enqueue_slot(slot_idx).is_err() {
                let _ = mb.free_slot(slot_idx);
                return false;
            }
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_thread(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

fn send_to_thread_id(dest_thread_id: u64, sender_handle: u64, buf_ptr: u64, len: u64) -> u64 {
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

    // NOTE:
    // - 宛先スロットに加えて世代番号をメッセージへ埋め込む。
    // - これにより、送信先終了後に同一スロットへ別スレッドが再利用されても誤配送されない。
    // - 送信時点と受信時点で世代不一致なら古いメッセージとして破棄される。

    // データをユーザー空間からコピー
    let mut data = [0u8; MAX_MSG_SIZE];
    if len > 0 && buf_ptr != 0 {
        if let Err(err) = crate::syscall::copy_from_user(buf_ptr, &mut data[..len]) {
            return err;
        }
    }

    let mut boxes = MAILBOXES.lock();
    if boxes[idx]
        .push_message(
            sender_handle,
            dest_thread_id,
            idx as u16,
            dest_generation,
            &data[..len],
        )
        .is_err()
    {
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
        crate::task::wake_thread(crate::task::ThreadId::from_u64(waiter));
    }

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

fn map_external_pages_for_receiver(
    receiver_tid: u64,
    map_start_hint: u64,
    total: u64,
    ext_pages_count: u16,
    ext_pages: &[u64; MAX_EXT_PAGES],
) -> Result<ExternalPageMapping, u64> {
    if ext_pages_count == 0 || ext_pages_count as usize > ext_pages.len() {
        return Err(EINVAL);
    }
    if total == 0 {
        return Err(EINVAL);
    }
    let max_bytes = (ext_pages_count as u64).saturating_mul(0x1000);
    if total > max_bytes {
        return Err(EINVAL);
    }

    let target_pid = crate::task::thread_to_process_id(receiver_tid).ok_or(EINVAL)?;
    let page_span = (ext_pages_count as u64).saturating_mul(0x1000);

    let _ = map_start_hint; // 受信側の安全のためヒントは無視して自動配置する
    let (virt_addr, page_table, reserved_heap_old, reserved_heap_new) =
        match crate::task::with_process_mut(target_pid, |p| {
            let base = if p.heap_end() < 0x7100_0000_0000u64 {
                0x7100_0000_0000u64
            } else {
                p.heap_end()
            };
            let virt_addr = base
                .checked_add(0xfff)
                .map(|v| v & !0xfffu64)
                .ok_or(EINVAL)?;
            let new_end = virt_addr.checked_add(page_span).ok_or(EINVAL)?;
            let pt = p.page_table().ok_or(EINVAL)?;
            let old_end = p.heap_end();
            p.set_heap_end(new_end);
            Ok((virt_addr, pt, old_end, new_end))
        }) {
            Some(Ok(v)) => (v.0, v.1, Some(v.2), Some(v.3)),
            Some(Err(e)) => return Err(e),
            None => return Err(EINVAL),
        };

    for i in 0..(ext_pages_count as usize) {
        let target_virt = virt_addr + (i as u64 * 0x1000);
        let phys_addr = ext_pages[i];
        if crate::mem::paging::map_page_in_table(page_table, target_virt, phys_addr, true, false)
            .is_err()
        {
            for j in 0..i {
                let rollback_virt = virt_addr + (j as u64 * 0x1000);
                let _ = crate::mem::paging::unmap_page_in_table(page_table, rollback_virt);
            }
            if let (Some(old_end), Some(new_end)) = (reserved_heap_old, reserved_heap_new) {
                let _ = crate::task::with_process_mut(target_pid, |p| {
                    if p.heap_end() == new_end {
                        p.set_heap_end(old_end);
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
        old_end: reserved_heap_old.unwrap_or(0),
        new_end: reserved_heap_new.unwrap_or(0),
        page_count: ext_pages_count as usize,
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
            if p.heap_end() == self.new_end {
                p.set_heap_end(self.old_end);
            }
        });
    }
}

fn prepare_external_pages_for_user(
    receiver_tid: u64,
    recv_buf: &mut [u8],
    copy_len: usize,
    ext_pages_count: u16,
    ext_pages: &[u64; MAX_EXT_PAGES],
) -> Result<(usize, Option<ExternalPageMapping>), u64> {
    if ext_pages_count == 0 {
        return Ok((copy_len, None));
    }
    crate::debug!(
        "[IPC RCV] prepare_external_pages_for_user receiver={} copy_len={} ext_pages_count={}",
        receiver_tid,
        copy_len,
        ext_pages_count
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
    let mapped_addr = map_external_pages_for_receiver(
        receiver_tid,
        map_start_hint,
        total,
        ext_pages_count,
        ext_pages,
    )?;
    recv_buf[0..8].copy_from_slice(&mapped_addr.virt_addr.to_le_bytes());
    recv_buf[8..16].copy_from_slice(&total.to_le_bytes());
    Ok((16, Some(mapped_addr)))
}

fn recv_from_thread_nonblocking(
    receiver_thread_id: u64,
    caller_thread_id: u64,
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

    let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
    let mut recv_buf = vec![0u8; MAX_MSG_SIZE];
    let (from, copy_len, ext_pages_count, ext_pages) = {
        let mut boxes = MAILBOXES.lock();
        match boxes[idx].pop_valid_for_receiver_copy(
            receiver_thread_id,
            idx as u16,
            receiver_generation,
            &mut recv_buf[..max_copy],
        ) {
            Some(v) => {
                if let Some((caller_idx, _)) =
                    crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                {
                    if caller_idx < MAX_THREADS {
                        boxes[caller_idx].reply_to = v.0;
                    }
                }
                v
            }
            None => return EAGAIN,
        }
    };
    let (copy_len, mapping) = match prepare_external_pages_for_user(
        receiver_thread_id,
        &mut recv_buf,
        copy_len,
        ext_pages_count,
        &ext_pages,
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if copy_len > 0 && buf_ptr != 0 {
        if let Err(err) = crate::syscall::copy_to_user(buf_ptr, &recv_buf[..copy_len]) {
            if let Some(mapping) = mapping.as_ref() {
                mapping.rollback();
            }
            return err;
        }
    }
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
) -> u64 {
    let (idx, receiver_generation) =
        match crate::task::thread_slot_index_and_generation_by_u64(receiver_thread_id) {
            Some(v) => v,
            None => return EINVAL,
        };

    if idx >= MAX_THREADS || idx > (u16::MAX as usize) {
        return EINVAL;
    }

    let mut recv_buf = [0u8; MAX_MSG_SIZE];
    loop {
        let max_copy = core::cmp::min(max_len as usize, ipc_max_msg_size());
        let recv = {
            let mut boxes = MAILBOXES.lock();
            match boxes[idx].pop_valid_for_receiver_copy(
                receiver_thread_id,
                idx as u16,
                receiver_generation,
                &mut recv_buf[..max_copy],
            ) {
                Some(v) => {
                    if let Some((caller_idx, _)) =
                        crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                    {
                        if caller_idx < MAX_THREADS {
                            boxes[caller_idx].reply_to = v.0;
                        }
                    }
                    Some(v)
                }
                None => {
                    boxes[idx].waiter = caller_thread_id;
                    None
                }
            }
        };

        match recv {
            Some((from, copy_len, ext_pages_count, ext_pages)) => {
                let (copy_len, mapping) = match prepare_external_pages_for_user(
                    receiver_thread_id,
                    &mut recv_buf,
                    copy_len,
                    ext_pages_count,
                    &ext_pages,
                ) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if copy_len > 0 && buf_ptr != 0 {
                    if let Err(err) = crate::syscall::copy_to_user(buf_ptr, &recv_buf[..copy_len]) {
                        if let Some(mapping) = mapping.as_ref() {
                            mapping.rollback();
                        }
                        return err;
                    }
                }
                crate::debug!(
                    "[IPC RECV] tid={} from={} len={} data={:02x?}",
                    receiver_thread_id,
                    from,
                    copy_len,
                    &recv_buf[..core::cmp::min(copy_len, 16)]
                );
                return (from << 32) | (copy_len as u64);
            }
            None => {
                {
                    let mut boxes = MAILBOXES.lock();
                    if let Some((from, copy_len, ext_pages_count, ext_pages)) = boxes[idx]
                        .pop_valid_for_receiver_copy(
                            receiver_thread_id,
                            idx as u16,
                            receiver_generation,
                            &mut recv_buf[..max_copy],
                        )
                    {
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                        if let Some((caller_idx, _)) =
                            crate::task::thread_slot_index_and_generation_by_u64(caller_thread_id)
                        {
                            if caller_idx < MAX_THREADS {
                                boxes[caller_idx].reply_to = from;
                            }
                        }
                        drop(boxes);
                        let (copy_len, mapping) = match prepare_external_pages_for_user(
                            receiver_thread_id,
                            &mut recv_buf,
                            copy_len,
                            ext_pages_count,
                            &ext_pages,
                        ) {
                            Ok(v) => v,
                            Err(e) => return e,
                        };
                        if copy_len > 0 && buf_ptr != 0 {
                            if let Err(err) =
                                crate::syscall::copy_to_user(buf_ptr, &recv_buf[..copy_len])
                            {
                                if let Some(mapping) = mapping.as_ref() {
                                    mapping.rollback();
                                }
                                return err;
                            }
                        }
                        crate::debug!(
                            "[IPC RECV] tid={} from={} len={}",
                            receiver_thread_id,
                            from,
                            copy_len
                        );
                        return (from << 32) | (copy_len as u64);
                    }
                }
                if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(
                    caller_thread_id,
                )) {
                    crate::task::yield_now();
                } else {
                    {
                        let mut boxes = MAILBOXES.lock();
                        if boxes[idx].waiter == caller_thread_id {
                            boxes[idx].waiter = 0;
                        }
                    }
                    return 0;
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
    recv_from_thread_nonblocking(receiver, receiver, buf_ptr, max_len)
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
    recv_blocking_for_thread(receiver, receiver, buf_ptr, max_len)
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
        let mut boxes = MAILBOXES.lock();
        boxes[idx]
            .pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
            )
            .map(|(_, n)| n)
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
            let mut boxes = MAILBOXES.lock();
            match boxes[idx].pop_from_sender_copy(
                sender_thread_id,
                receiver_u64,
                idx as u16,
                receiver_generation,
                buf,
            ) {
                Some((_, n)) => Some(n),
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
                    let mut boxes = MAILBOXES.lock();
                    if let Some((_, n)) = boxes[idx].pop_from_sender_copy(
                        sender_thread_id,
                        receiver_u64,
                        idx as u16,
                        receiver_generation,
                        buf,
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
                    let mut boxes = MAILBOXES.lock();
                    if boxes[idx].waiter == receiver_u64 {
                        boxes[idx].waiter = 0;
                    }
                    return Err(EAGAIN);
                }
            }
        }
    }
}
