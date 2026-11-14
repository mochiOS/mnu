//! Endpoint identity, owned messages, mailboxes and kernel IPC transport.

use crate::interrupt::spinlock::{SpinLock, SpinLockGuard};
use alloc::alloc::{alloc, Layout};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub(crate) mod lifetime;
pub(crate) mod provider;

use crate::task::{HandleRights, KernelObject, ObjectHandle, ObjectHandleEntry};

pub(crate) const MAX_THREADS: usize = crate::task::ThreadQueue::MAX_THREADS;
pub(crate) const MAILBOX_CAP: usize = 64;
pub(crate) const MESSAGE_CACHE_CAP: usize = MAILBOX_CAP;
pub(crate) const MAX_MSG_SIZE: usize = crate::config::IPC_MESSAGE_CAPACITY;
pub(crate) const MAX_OBJECT_HANDLES: usize = mnu_abi::IPC_MAX_OBJECT_HANDLES;

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
pub(crate) struct EndpointRecord {
    pub(crate) thread_id: u64,
    pub(crate) slot: u16,
    pub(crate) generation: u64,
    pub(crate) rights: EndpointRights,
}

// Global endpoint IDs occupy a disjoint opaque range from process-local
// object Handles. Decode addressing policy at the syscall boundary.
// The sender handle is carried in the upper 32 bits of a successful syscall
// result, so it must also stay below bit 31 to keep that result non-negative.
pub(crate) const ENDPOINT_HANDLE_BASE: u64 = 0x4000_0000;
pub(crate) const ENDPOINT_HANDLE_LIMIT: u64 = 0x7fff_ffff;
pub(crate) static NEXT_ENDPOINT_HANDLE: AtomicU64 = AtomicU64::new(ENDPOINT_HANDLE_BASE);
pub(crate) static NEXT_CALL_ID: AtomicU64 = AtomicU64::new(1);
pub(crate) static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);
pub(crate) static ENDPOINTS: Mutex<Option<BTreeMap<u64, EndpointRecord>>> = Mutex::new(None);
// Keys are globally unique IPC lifetimes, not reusable native thread IDs.
pub(crate) static DEFAULT_ENDPOINTS_BY_GENERATION: Mutex<Option<BTreeMap<u64, u64>>> =
    Mutex::new(None);

pub fn endpoint_for_thread(thread_id: u64) -> Option<IpcEndpoint> {
    let (slot, generation) = crate::task::ipc_slot_index_and_generation_by_u64(thread_id)?;
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
    match crate::task::thread::live_ipc_slot_index_and_generation_by_u64(endpoint.thread_id) {
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

pub(crate) fn with_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, EndpointRecord>) -> R) -> R {
    let mut guard = ENDPOINTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub(crate) fn with_default_endpoints_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, u64>) -> R) -> R {
    let mut guard = DEFAULT_ENDPOINTS_BY_GENERATION.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub(crate) fn endpoint_record_is_valid(record: &EndpointRecord) -> bool {
    endpoint_is_valid(IpcEndpoint {
        thread_id: record.thread_id,
        slot: record.slot,
        generation: record.generation,
    })
}

pub(crate) fn endpoint_record_from_handle(handle: u64) -> Option<EndpointRecord> {
    with_endpoints_mut(|endpoints| endpoints.get(&handle).copied())
        .filter(|record| endpoint_record_is_valid(record))
}

pub(crate) fn endpoint_rights_for_thread(thread_id: u64) -> EndpointRights {
    let Some(pid) = crate::task::thread_to_process_id(thread_id) else {
        return EndpointRights::empty();
    };
    endpoint_rights_for_process(pid.as_u64())
}

pub(crate) fn endpoint_handle_for_thread(thread_id: u64) -> Option<u64> {
    let endpoint = endpoint_for_thread(thread_id)?;
    let handle = with_default_endpoints_mut(|defaults| defaults.get(&endpoint.generation).copied());
    let Some(handle) = handle else {
        return None;
    };
    if endpoint_record_from_handle(handle)
        .is_some_and(|record| record_matches_endpoint(&record, endpoint))
    {
        Some(handle)
    } else {
        with_default_endpoints_mut(|defaults| {
            if defaults.get(&endpoint.generation).copied() == Some(handle) {
                defaults.remove(&endpoint.generation);
            }
        });
        None
    }
}

pub(crate) fn ensure_endpoint_for_thread(thread_id: u64) -> Option<u64> {
    let endpoint = endpoint_for_thread(thread_id)?;
    let rights = endpoint_rights_for_thread(thread_id);
    // Serialize creation of a default for this lifetime. Concurrent callers
    // must agree on the sender identity used to authenticate synchronous replies.
    let handle = with_default_endpoints_mut(|defaults| {
        if !endpoint_is_valid(endpoint) {
            return None;
        }
        if let Some(handle) = defaults.get(&endpoint.generation).copied() {
            if endpoint_record_from_handle(handle)
                .is_some_and(|record| record_matches_endpoint(&record, endpoint))
            {
                return Some(handle);
            }
        }
        let handle = NEXT_ENDPOINT_HANDLE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                (next <= ENDPOINT_HANDLE_LIMIT).then(|| next + 1)
            })
            .ok()?;
        let record = EndpointRecord {
            thread_id,
            slot: endpoint.slot,
            generation: endpoint.generation,
            rights,
        };
        with_endpoints_mut(|endpoints| {
            endpoints.insert(handle, record);
        });
        defaults.insert(endpoint.generation, handle);
        Some(handle)
    })?;
    // Replacement may commit while creating this record. Its generation key
    // cannot overwrite the new image's default; clean a late old insertion.
    if !endpoint_is_valid(endpoint) {
        retire_endpoint_records(endpoint);
        return None;
    }
    Some(handle)
}

pub(crate) fn record_matches_endpoint(record: &EndpointRecord, endpoint: IpcEndpoint) -> bool {
    record.thread_id == endpoint.thread_id
        && record.slot == endpoint.slot
        && record.generation == endpoint.generation
}

pub(crate) fn retire_endpoint_records(endpoint: IpcEndpoint) {
    // Same lock order as default creation; no thread/queue lock is held.
    with_default_endpoints_mut(|defaults| {
        defaults.remove(&endpoint.generation);
        with_endpoints_mut(|endpoints| {
            endpoints.retain(|_, record| !record_matches_endpoint(record, endpoint));
        });
    });
}

pub fn resolve_endpoint_handle(dest: u64) -> Option<u64> {
    endpoint_record_from_handle(dest).map(|record| record.thread_id)
}

pub fn resolve_sender_thread_id(sender: u64) -> Option<u64> {
    resolve_endpoint_handle(sender)
        .or_else(|| crate::task::ipc_slot_index_and_generation_by_u64(sender).map(|_| sender))
}

pub(crate) fn endpoint_wait_ready(endpoint: IpcEndpoint) -> Result<bool, u64> {
    use mnu_abi::status::Error;
    if !endpoint_is_valid(endpoint) {
        return Err(Error::NotFound.into_raw());
    }
    let mailboxes = lock_mailboxes();
    let mailbox = mailboxes
        .get(endpoint.slot as usize)
        .ok_or_else(|| Error::InvalidArgument.into_raw())?;
    Ok(mailbox.count > 0)
}

pub(crate) fn register_endpoint_waiter(
    endpoint: IpcEndpoint,
    waiter: crate::task::ThreadId,
) -> Result<(), u64> {
    use mnu_abi::status::Error;
    if !endpoint_is_valid(endpoint) {
        return Err(Error::NotFound.into_raw());
    }
    if endpoint.thread_id != waiter.as_u64() {
        return Err(Error::AccessDenied.into_raw());
    }
    let mut mailboxes = lock_mailboxes();
    let mailbox = mailboxes
        .get_mut(endpoint.slot as usize)
        .ok_or_else(|| Error::InvalidArgument.into_raw())?;
    if mailbox.waiter != 0 && mailbox.waiter != waiter.as_u64() {
        return Err(Error::ResourceUnavailable.into_raw());
    }
    mailbox.waiter = waiter.as_u64();
    Ok(())
}

pub(crate) fn remove_endpoint_waiter(endpoint: IpcEndpoint, waiter: crate::task::ThreadId) {
    if !endpoint_is_valid(endpoint) {
        return;
    }
    let mut mailboxes = lock_mailboxes();
    if let Some(mailbox) = mailboxes.get_mut(endpoint.slot as usize) {
        if mailbox.waiter == waiter.as_u64() {
            mailbox.waiter = 0;
        }
    }
}

pub(crate) fn ipc_mailbox_cap() -> usize {
    // At least one ordinary message and one synchronous reply must fit.
    crate::config::kernel()
        .ipc
        .mailbox_cap
        .clamp(2, MAILBOX_CAP)
}

#[inline]
pub(crate) fn ipc_max_msg_size() -> usize {
    crate::config::kernel().ipc.max_msg_size.min(MAX_MSG_SIZE)
}

#[inline]
pub(crate) fn record_ipc_copy(bytes: usize) {
    crate::performance::increment(
        crate::performance::CounterMetric::IpcBytesCopied,
        bytes as u64,
    );
}

pub(crate) fn export_object_handle(
    process_id: crate::task::ProcessId,
    handle: ObjectHandle,
    requested: HandleRights,
) -> Result<ObjectHandleEntry, u64> {
    use mnu_abi::status::Error;

    crate::task::with_process(process_id, |process| {
        let source = process
            .object_handles()
            .get(handle)
            .ok_or_else(|| Error::InvalidArgument.into_raw())?;
        if !source.rights().contains(HandleRights::TRANSFER) || !source.rights().contains(requested)
        {
            return Err(Error::AccessDenied.into_raw());
        }
        process
            .object_handles()
            .export_restricted(handle, requested)
            .ok_or_else(|| Error::AccessDenied.into_raw())
    })
    .ok_or_else(|| Error::NotReady.into_raw())?
}

#[derive(Debug)]
pub(crate) struct ObjectHandleAttachments {
    pub(crate) count: usize,
    pub(crate) delivery_flags: u32,
    pub(crate) handles: [Option<ObjectHandleEntry>; MAX_OBJECT_HANDLES],
}

impl ObjectHandleAttachments {
    pub(crate) const fn empty() -> Self {
        Self {
            count: 0,
            delivery_flags: 0,
            handles: [const { None }; MAX_OBJECT_HANDLES],
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

#[derive(Debug)]
pub struct Message {
    pub(crate) message_id: u64,
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) to_slot: u16,
    pub(crate) to_generation: u64,
    pub(crate) is_reply: bool,
    pub(crate) expects_reply: bool,
    pub(crate) call_id: u64,
    pub(crate) len: usize,
    pub(crate) data: [u8; MAX_MSG_SIZE],
    pub(crate) object_handles: ObjectHandleAttachments,
}

impl Message {
    pub(crate) const fn empty() -> Self {
        Self {
            message_id: 0,
            from: 0,
            to: 0,
            to_slot: 0,
            to_generation: 0,
            is_reply: false,
            expects_reply: false,
            call_id: 0,
            len: 0,
            data: [0; MAX_MSG_SIZE],
            object_handles: ObjectHandleAttachments::empty(),
        }
    }
}

pub(crate) struct UserReceive {
    pub(crate) from: u64,
    pub(crate) copy_len: usize,
    pub(crate) expects_reply: bool,
    pub(crate) object_handles: ObjectHandleAttachments,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplyTarget {
    pub(crate) endpoint: u64,
    pub(crate) call_id: u64,
    pub(crate) source: IpcEndpoint,
}

#[derive(Debug)]
pub(crate) struct Mailbox {
    pub(crate) head: usize,
    pub(crate) tail: usize,
    pub(crate) count: usize,
    pub(crate) queue: [u8; MAILBOX_CAP],
    pub(crate) slots: [Option<Box<Message>>; MAILBOX_CAP],
    pub(crate) free: [u8; MAILBOX_CAP],
    pub(crate) free_count: usize,
    /// メッセージ待ちでスリープ中のスレッドID (0=なし)
    pub(crate) waiter: u64,
    /// Endpoints whose synchronous calls this thread has received and may
    /// answer later.
    pub(crate) reply_targets: Vec<ReplyTarget>,
    pub(crate) reply_owner: Option<(u64, u64)>,
}

impl Mailbox {
    pub(crate) const fn new() -> Self {
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
            reply_owner: None,
        }
    }

    pub(crate) fn add_reply_target(
        &mut self,
        endpoint: u64,
        call_id: u64,
        owner: (u64, u64),
    ) -> Result<Option<ReplyTarget>, u64> {
        use mnu_abi::status::Error;
        // Mailboxes are indexed by reusable thread slots. Reply authority may
        // never survive into a different thread or a new slot generation.
        if self.reply_owner != Some(owner) {
            self.reply_targets.clear();
            self.reply_owner = Some(owner);
        }
        self.reply_targets
            .retain(|target| endpoint_is_valid(target.source));
        // A caller can retire after enqueue. Consume its request without
        // minting stale reply authority rather than wedging the receive queue.
        let Some(record) = endpoint_record_from_handle(endpoint) else {
            return Ok(None);
        };
        let target = ReplyTarget {
            endpoint,
            call_id,
            source: IpcEndpoint {
                thread_id: record.thread_id,
                slot: record.slot,
                generation: record.generation,
            },
        };
        if !endpoint_is_valid(target.source) {
            return Ok(None);
        }
        if self.reply_targets.contains(&target) {
            return Ok(None);
        }
        if endpoint == 0 || call_id == 0 || self.reply_targets.len() >= MAILBOX_CAP {
            return Err(Error::LimitExceeded.into_raw());
        }
        self.reply_targets
            .try_reserve(1)
            .map_err(|_| Error::ResourceUnavailable.into_raw())?;
        self.reply_targets.push(target);
        Ok(Some(target))
    }

    pub(crate) fn reply_target(&self, endpoint: u64, owner: (u64, u64)) -> Option<ReplyTarget> {
        if self.reply_owner != Some(owner) {
            return None;
        }
        self.reply_targets
            .iter()
            .copied()
            .find(|target| target.endpoint == endpoint)
    }

    pub(crate) fn remove_reply_target(&mut self, target: ReplyTarget) {
        if let Some(index) = self.reply_targets.iter().position(|value| *value == target) {
            self.reply_targets.swap_remove(index);
        }
    }

    pub(crate) fn reserve_slot(&mut self, is_reply: bool) -> Option<usize> {
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

    pub(crate) fn alloc_slot(&mut self) -> Option<usize> {
        let message = allocate_message()?;
        let Some(idx) = self.reserve_slot(false) else {
            release_message(message);
            return None;
        };
        self.slots[idx] = Some(message);
        Some(idx)
    }

    /// Rejected messages remain caller-owned so their attached resources can
    /// be released after the mailbox lock is dropped. None means corrupted
    /// storage has already been retired by quarantine.
    pub(crate) fn enqueue_message(
        &mut self,
        message: Box<Message>,
    ) -> Result<(), Option<Box<Message>>> {
        let Some(slot_idx) = self.reserve_slot(message.is_reply) else {
            return Err(Some(message));
        };
        self.slots[slot_idx] = Some(message);
        if self.enqueue_slot(slot_idx).is_err() {
            return Err(self.take_slot(slot_idx));
        }
        Ok(())
    }

    pub(crate) fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            release_message(message);
        }
        *self = Self::new();
    }

    pub(crate) fn free_slot(&mut self, idx: usize) -> bool {
        match self.take_slot(idx) {
            Some(message) => {
                release_message(message);
                true
            }
            None => false,
        }
    }

    pub(crate) fn take_slot(&mut self, idx: usize) -> Option<Box<Message>> {
        if idx >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: slot index out of range");
            return None;
        }
        if self.free_count >= MAILBOX_CAP {
            self.quarantine("ipc mailbox free list corrupted: free_count overflow");
            return None;
        }
        for i in 0..self.free_count {
            if self.free[i] as usize == idx {
                self.quarantine("ipc mailbox free list corrupted: double free");
                return None;
            }
        }

        let Some(message) = self.slots[idx].take() else {
            self.quarantine("ipc mailbox slot missing during free");
            return None;
        };
        self.free[self.free_count] = idx as u8;
        self.free_count += 1;
        Some(message)
    }

    pub(crate) fn enqueue_slot(&mut self, slot_idx: usize) -> Result<(), ()> {
        if self.count >= MAILBOX_CAP {
            return Err(());
        }
        let message = self
            .slots
            .get_mut(slot_idx)
            .and_then(Option::as_deref_mut)
            .ok_or(())?;
        if message.message_id == 0 {
            // Rotating an existing queue entry keeps its identity. Never wrap
            // and let a delayed receive commit consume a reused allocation.
            message.message_id = NEXT_MESSAGE_ID
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .map_err(|_| ())?;
        }
        self.queue[self.tail] = slot_idx as u8;
        self.tail = (self.tail + 1) % MAILBOX_CAP;
        self.count += 1;
        Ok(())
    }

    pub(crate) fn dequeue_slot(&mut self) -> Option<usize> {
        if self.count == 0 {
            return None;
        }
        let idx = self.queue[self.head] as usize;
        self.head = (self.head + 1) % MAILBOX_CAP;
        self.count -= 1;
        Some(idx)
    }

    /// Detach only the retired destination's messages. The caller releases
    /// their attachments after dropping the mailbox lock. Filtering preserves
    /// FIFO order for a newer generation already occupying this reusable slot.
    pub(crate) fn retire_destination(
        &mut self,
        endpoint: IpcEndpoint,
    ) -> [Option<Box<Message>>; MAILBOX_CAP] {
        let mut retired = [const { None }; MAILBOX_CAP];
        if self.count > MAILBOX_CAP {
            self.quarantine("ipc mailbox count exceeds capacity during retirement");
            return retired;
        }
        let count = self.count;
        for output in retired.iter_mut().take(count) {
            let Some(slot) = self.dequeue_slot() else {
                break;
            };
            let Some(message) = self.slots.get(slot).and_then(Option::as_ref) else {
                self.quarantine("ipc mailbox retirement points to an empty slot");
                break;
            };
            if message.to == endpoint.thread_id
                && message.to_slot == endpoint.slot
                && message.to_generation == endpoint.generation
            {
                *output = self.take_slot(slot);
                if output.is_none() {
                    break;
                }
            } else if self.enqueue_slot(slot).is_err() {
                self.quarantine("ipc mailbox retirement could not preserve queue");
                break;
            }
        }
        if self.reply_owner == Some((endpoint.thread_id, endpoint.generation)) {
            self.reply_targets.clear();
            self.reply_owner = None;
        }
        retired
    }

    pub(crate) fn push_message(
        &mut self,
        from: u64,
        to: u64,
        to_slot: u16,
        to_generation: u64,
        data: &[u8],
        is_reply: bool,
        expects_reply: bool,
        call_id: u64,
        delivery_flags: u32,
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
        msg.object_handles = ObjectHandleAttachments::empty();
        msg.object_handles.delivery_flags = delivery_flags;
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

    pub(crate) fn pop_reply_copy(
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
    pub(crate) fn take_waiter(&mut self) -> u64 {
        let w = self.waiter;
        self.waiter = 0;
        w
    }
}

pub(crate) struct MessageCache {
    pub(crate) slots: [Option<Box<Message>>; MESSAGE_CACHE_CAP],
    pub(crate) count: usize,
}

impl MessageCache {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { None }; MESSAGE_CACHE_CAP],
            count: 0,
        }
    }

    pub(crate) fn take(&mut self) -> Option<Box<Message>> {
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

    pub(crate) fn put(&mut self, message: Box<Message>) -> Result<(), Box<Message>> {
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

    pub(crate) fn quarantine(&mut self, reason: &'static str) {
        crate::audit::log(crate::audit::AuditEventKind::Quarantine, reason);
        for message in self.slots.iter_mut().filter_map(Option::take) {
            drop(wipe_message(message));
        }
        self.count = 0;
    }
}

pub(crate) fn wipe_message(mut message: Box<Message>) -> Box<Message> {
    // Volatile stores do not drop the overwritten value. Release any authority
    // still owned by a discarded message before erasing its reusable storage.
    drop(core::mem::replace(
        &mut message.object_handles,
        ObjectHandleAttachments::empty(),
    ));
    // The volatile replacement keeps message contents from surviving in a
    // reusable kernel heap allocation after the queue releases them.
    unsafe {
        core::ptr::write_volatile(message.as_mut(), Message::empty());
    }
    message
}

pub(crate) fn release_message(message: Box<Message>) {
    let message = wipe_message(message);
    if let Err(message) = MESSAGE_CACHE.lock().put(message) {
        drop(message);
    }
}

pub(crate) fn allocate_message() -> Option<Box<Message>> {
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

pub(crate) static MESSAGE_CACHE: SpinLock<MessageCache> = SpinLock::new(MessageCache::new());
pub(crate) static MAILBOXES: SpinLock<[Mailbox; MAX_THREADS]> =
    SpinLock::new([const { Mailbox::new() }; MAX_THREADS]);

#[inline]
pub(crate) fn lock_mailboxes() -> SpinLockGuard<'static, [Mailbox; MAX_THREADS]> {
    #[cfg(feature = "performance-instrumentation")]
    let start = crate::performance::timestamp();
    let guard = MAILBOXES.lock();
    #[cfg(feature = "performance-instrumentation")]
    crate::performance::record_latency(crate::performance::LatencyMetric::IpcLockWait, start);
    guard
}

/// Commit the kept native thread's new IPC lifetime after image installation.
/// Changing the generation precedes mailbox retirement: an old send which
/// already validated under MAILBOXES must finish before retirement acquires
/// that lock; later sends fail validation. Purge completes before user entry.
pub(crate) fn replace_thread_image_endpoint(
    thread: crate::task::ThreadId,
    generation: crate::task::ipc_generation::Reserved,
) {
    if let Some((slot, previous)) =
        crate::task::thread::replace_ipc_generation(thread, generation.into_raw())
    {
        // This is the kept current thread, still inside image replacement.
        // It cannot yet have installed a new-image inbox wait. Delayed generic
        // retirement cannot infer that from the unchanged native TID alone.
        {
            let mut boxes = lock_mailboxes();
            if boxes[slot].waiter == thread.as_u64() {
                boxes[slot].waiter = 0;
            }
        }
        retire_endpoint(IpcEndpoint {
            thread_id: thread.as_u64(),
            slot: slot as u16,
            generation: previous,
        });
    }
    lifetime::remove_waiter(thread);
}

/// The caller has published termination and released the thread queue lock.
/// Exact destination filtering also tolerates delayed cleanup after slot reuse.
pub(crate) fn retire_endpoint(endpoint: IpcEndpoint) {
    if (endpoint.slot as usize) < MAX_THREADS {
        let retired = {
            let mut boxes = lock_mailboxes();
            for mailbox in boxes.iter_mut() {
                mailbox
                    .reply_targets
                    .retain(|target| target.source != endpoint);
            }
            let mailbox = &mut boxes[endpoint.slot as usize];
            let retired = mailbox.retire_destination(endpoint);
            let current = crate::task::ipc_slot_index_and_generation_by_u64(endpoint.thread_id);
            if mailbox.waiter == endpoint.thread_id
                && current.is_none_or(|(slot, generation)| {
                    slot == endpoint.slot as usize && generation == endpoint.generation
                })
            {
                mailbox.waiter = 0;
            }
            retired
        };
        retire_endpoint_records(endpoint);
        for message in retired.into_iter().flatten() {
            release_message(message);
        }
    }
    lifetime::retire(endpoint);
}

/// カーネル内部からIPC送信（ユーザー空間コピー不要）
pub fn send_from_kernel(dest_thread_id: u64, data: &[u8]) -> bool {
    let len = data.len();
    if len > ipc_max_msg_size() {
        return false;
    }
    let (idx, dest_generation) =
        match crate::task::ipc_slot_index_and_generation_by_u64(dest_thread_id) {
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
        if !endpoint_is_valid(IpcEndpoint {
            thread_id: dest_thread_id,
            slot: idx as u16,
            generation: dest_generation,
        }) {
            return false;
        }
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
                0,
            )
            .is_ok()
        {
            let waiter = mb.take_waiter();
            if waiter != 0 {
                crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
            }
            true
        } else {
            false
        }
    })
}

/// Sends one non-blocking message to an exact provider endpoint identity.
pub(crate) fn send_provider_from_kernel(endpoint: IpcEndpoint, data: &[u8]) -> bool {
    if data.len() > ipc_max_msg_size() || !endpoint_is_valid(endpoint) {
        return false;
    }
    // Release notifications expect no reply. Reuse an existing sender, or the
    // already supported kernel/no-sender value; never allocate endpoint maps
    // while reclaiming a reference under memory pressure.
    let sender = crate::task::current_thread_id()
        .and_then(|thread| endpoint_handle_for_thread(thread.as_u64()))
        .unwrap_or(0);
    let mut mailboxes = lock_mailboxes();
    if !endpoint_is_valid(endpoint) {
        return false;
    }
    let Some(mailbox) = mailboxes.get_mut(endpoint.slot as usize) else {
        return false;
    };
    if mailbox
        .push_message(
            sender,
            endpoint.thread_id,
            endpoint.slot,
            endpoint.generation,
            data,
            false,
            false,
            0,
            mnu_abi::IPC_DELIVERY_NATIVE_OBJECT,
        )
        .is_err()
    {
        return false;
    }
    let waiter = mailbox.take_waiter();
    drop(mailboxes);
    if waiter != 0 {
        crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
    }
    true
}

/// Performs a synchronous kernel-originated call against an exact endpoint
/// identity rather than a process-visible endpoint handle.
pub(crate) fn call_provider_from_kernel(
    endpoint: IpcEndpoint,
    request: &[u8],
    reply: &mut [u8],
) -> Result<usize, u64> {
    use mnu_abi::status::Error;

    if !endpoint_is_valid(endpoint) {
        return Err(Error::NotFound.into_raw());
    }
    let expected_sender =
        ensure_endpoint_for_thread(endpoint.thread_id).ok_or_else(|| Error::NotReady.into_raw())?;
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    call_endpoint_with_attachments_from_kernel(
        endpoint,
        expected_sender,
        request,
        reply,
        attachments,
    )
}

/// Attach only handles from the authenticated caller's own table, through the
/// same attenuation enforcement as user-originated IPC.
pub(crate) fn call_provider_with_handle_from_kernel(
    endpoint: IpcEndpoint,
    request: &[u8],
    reply: &mut [u8],
    handle: ObjectHandle,
    requested: HandleRights,
) -> Result<usize, u64> {
    use mnu_abi::status::Error;

    if !endpoint_is_valid(endpoint) {
        return Err(Error::NotFound.into_raw());
    }
    let process_id = crate::task::current_process_id().ok_or_else(|| Error::NotReady.into_raw())?;
    let mut attachments = ObjectHandleAttachments::empty();
    attachments.handles[0] = Some(export_object_handle(process_id, handle, requested)?);
    attachments.count = 1;
    attachments.delivery_flags = mnu_abi::IPC_DELIVERY_NATIVE_OBJECT;
    let expected_sender =
        ensure_endpoint_for_thread(endpoint.thread_id).ok_or_else(|| Error::NotReady.into_raw())?;
    call_endpoint_with_attachments_from_kernel(
        endpoint,
        expected_sender,
        request,
        reply,
        attachments,
    )
}

pub(crate) fn call_endpoint_with_attachments_from_kernel(
    endpoint: IpcEndpoint,
    expected_sender: u64,
    request: &[u8],
    reply: &mut [u8],
    mut attachments: ObjectHandleAttachments,
) -> Result<usize, u64> {
    use mnu_abi::status::Error;

    if request.len() > ipc_max_msg_size() || reply.len() > ipc_max_msg_size() {
        return Err(Error::LimitExceeded.into_raw());
    }
    let caller = crate::task::current_thread_id()
        .ok_or_else(|| Error::NotReady.into_raw())?
        .as_u64();
    let _lifetime = lifetime::observe(endpoint, crate::task::ThreadId::from_u64(caller))?;
    let sender = ensure_endpoint_for_thread(caller).ok_or_else(|| Error::NotReady.into_raw())?;
    let call_id = NEXT_CALL_ID.fetch_add(1, Ordering::Relaxed).max(1);
    let (dest_slot, dest_generation) =
        crate::task::ipc_slot_index_and_generation_by_u64(endpoint.thread_id)
            .filter(|(slot, generation)| {
                *slot as u16 == endpoint.slot && *generation == endpoint.generation
            })
            .ok_or_else(|| Error::NotFound.into_raw())?;
    // Resolve the reply destination before publishing a request: an absent
    // caller slot cannot receive a result and must not cause external work.
    let (caller_slot, caller_generation) =
        crate::task::ipc_slot_index_and_generation_by_u64(caller)
            .ok_or_else(|| Error::NotReady.into_raw())?;
    loop {
        if !endpoint_is_valid(endpoint) {
            return Err(Error::NotFound.into_raw());
        }
        let mut mailboxes = lock_mailboxes();
        if !endpoint_is_valid(endpoint) {
            return Err(Error::NotFound.into_raw());
        }
        let mailbox = mailboxes
            .get_mut(dest_slot)
            .ok_or_else(|| Error::BackingFailure.into_raw())?;
        if let Some(slot) = mailbox.alloc_slot() {
            let Some(message) = mailbox.slots[slot].as_deref_mut() else {
                mailbox.quarantine("ipc mailbox allocated slot is missing");
                return Err(Error::BackingFailure.into_raw());
            };
            message.from = sender;
            message.to = endpoint.thread_id;
            message.to_slot = dest_slot as u16;
            message.to_generation = dest_generation;
            message.is_reply = false;
            message.expects_reply = true;
            message.call_id = call_id;
            message.len = request.len();
            message.data[..request.len()].copy_from_slice(request);
            record_ipc_copy(request.len());
            message.object_handles = attachments;
            if mailbox.enqueue_slot(slot).is_err() {
                // Keep ownership while retrying rather than discarding handles.
                let message = mailbox.slots[slot]
                    .as_deref_mut()
                    .ok_or_else(|| Error::BackingFailure.into_raw())?;
                attachments = core::mem::replace(
                    &mut message.object_handles,
                    ObjectHandleAttachments::empty(),
                );
                mailbox.free_slot(slot);
            } else {
                let waiter = mailbox.take_waiter();
                drop(mailboxes);
                if waiter != 0 {
                    crate::task::wake_registered_waiter(crate::task::ThreadId::from_u64(waiter));
                }
                break;
            }
        }
        drop(mailboxes);
        crate::task::yield_now();
    }
    loop {
        let received = {
            let mut mailboxes = lock_mailboxes();
            let mailbox = mailboxes
                .get_mut(caller_slot)
                .ok_or_else(|| Error::BackingFailure.into_raw())?;
            let received = mailbox.pop_reply_copy(
                expected_sender,
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
        if !endpoint_is_valid(endpoint) {
            let mut mailboxes = lock_mailboxes();
            if let Some(mailbox) = mailboxes.get_mut(caller_slot) {
                if mailbox.waiter == caller {
                    mailbox.waiter = 0;
                }
            }
            return Err(Error::NotFound.into_raw());
        }
        if crate::task::sleep_thread_unless_woken(crate::task::ThreadId::from_u64(caller)) {
            crate::task::yield_now();
        } else {
            let mut mailboxes = lock_mailboxes();
            let mailbox = mailboxes
                .get_mut(caller_slot)
                .ok_or_else(|| Error::BackingFailure.into_raw())?;
            if mailbox.waiter == caller {
                mailbox.waiter = 0;
            }
        }
    }
}
