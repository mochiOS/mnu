use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::fd_table::FileHandle;
use super::process::ProcessObject;
mod provider_release;

pub const PROCESS_MAX_OBJECT_HANDLES: usize = mnu_abi::PROCESS_MAX_OBJECT_HANDLES;

pub struct ProviderObject {
    pub endpoint_thread_id: u64,
    pub endpoint_slot: u16,
    pub endpoint_generation: u64,
    pub object_id: u64,
    registered: AtomicBool,
    release_ticket: Option<provider_release::Ticket>,
    io_options: AtomicU64,
    memory_identity: AtomicU64,
    memory_identity_unavailable: AtomicBool,
    signal_state: crate::interrupt::spinlock::SpinLock<ProviderSignalState>,
}

impl core::fmt::Debug for ProviderObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProviderObject")
            .field("endpoint_thread_id", &self.endpoint_thread_id)
            .field("endpoint_slot", &self.endpoint_slot)
            .field("endpoint_generation", &self.endpoint_generation)
            .field("object_id", &self.object_id)
            .field("io_options", &self.io_options())
            .field("signals", &self.signals())
            .finish()
    }
}

#[derive(Default)]
struct ProviderSignalState {
    signals: u64,
    waiters: Vec<super::ids::ThreadId>,
}

type ProviderKey = (u64, u16, u64, u64);

static PROVIDER_OBJECTS: crate::interrupt::spinlock::SpinLock<
    BTreeMap<ProviderKey, Weak<ProviderObject>>,
> = crate::interrupt::spinlock::SpinLock::new(BTreeMap::new());

#[derive(Clone, Copy)]
pub(crate) struct ProviderRelease {
    pub endpoint_thread_id: u64,
    pub endpoint_slot: u16,
    pub endpoint_generation: u64,
    pub object_id: u64,
}

static PENDING_PROVIDER_RELEASES: crate::interrupt::spinlock::SpinLock<provider_release::Pending> =
    crate::interrupt::spinlock::SpinLock::new(provider_release::Pending::new());

pub(crate) fn take_provider_releases() -> provider_release::Pending {
    let pending = core::mem::take(&mut *PENDING_PROVIDER_RELEASES.lock());
    pending.reversed()
}

pub(crate) fn requeue_provider_release(ticket: provider_release::Ticket) {
    PENDING_PROVIDER_RELEASES.lock().push(ticket);
}

impl Drop for ProviderObject {
    fn drop(&mut self) {
        let mut objects = PROVIDER_OBJECTS.lock();
        if objects
            .get(&self.key())
            .is_some_and(|object| core::ptr::eq(object.as_ptr(), self))
        {
            objects.remove(&self.key());
        }
        drop(objects);
        if !self.registered.load(Ordering::Acquire) {
            return;
        }
        if let Some(ticket) = self.release_ticket.take() {
            PENDING_PROVIDER_RELEASES.lock().push(ticket);
        }
    }
}

impl ProviderObject {
    pub(crate) fn new(
        endpoint_thread_id: u64,
        endpoint_slot: u16,
        endpoint_generation: u64,
        object_id: u64,
    ) -> Result<Self, u64> {
        let release_ticket = provider_release::Ticket::new(ProviderRelease {
            endpoint_thread_id,
            endpoint_slot,
            endpoint_generation,
            object_id,
        })?;
        Ok(Self {
            endpoint_thread_id,
            endpoint_slot,
            endpoint_generation,
            object_id,
            registered: AtomicBool::new(false),
            release_ticket: Some(release_ticket),
            io_options: AtomicU64::new(0),
            memory_identity: AtomicU64::new(0),
            memory_identity_unavailable: AtomicBool::new(false),
            signal_state: crate::interrupt::spinlock::SpinLock::new(ProviderSignalState::default()),
        })
    }

    fn key(&self) -> ProviderKey {
        (
            self.endpoint_thread_id,
            self.endpoint_slot,
            self.endpoint_generation,
            self.object_id,
        )
    }

    pub(crate) fn signals(&self) -> u64 {
        self.signal_state.lock().signals
    }

    pub(crate) fn io_options(&self) -> u64 {
        self.io_options.load(Ordering::Acquire)
    }

    pub(crate) fn set_io_options(&self, options: u64) {
        self.io_options.store(options, Ordering::Release);
    }

    pub(crate) fn memory_identity(&self) -> Option<u64> {
        let identity = self.memory_identity.load(Ordering::Acquire);
        (identity != 0).then_some(identity)
    }

    pub(crate) fn set_memory_identity(&self, identity: u64) {
        self.memory_identity.store(identity, Ordering::Release);
    }

    pub(crate) fn memory_identity_unavailable(&self) -> bool {
        self.memory_identity_unavailable.load(Ordering::Acquire)
    }

    pub(crate) fn set_memory_identity_unavailable(&self) {
        self.memory_identity_unavailable
            .store(true, Ordering::Release);
    }

    pub(crate) fn register_waiter(&self, waiter: super::ids::ThreadId) -> bool {
        let mut state = self.signal_state.lock();
        state
            .waiters
            .retain(|candidate| crate::task::thread_id_exists(candidate.as_u64()));
        if state.waiters.contains(&waiter) {
            return true;
        }
        if state.waiters.len() >= super::ThreadQueue::MAX_THREADS {
            return false;
        }
        state.waiters.push(waiter);
        true
    }

    pub(crate) fn remove_waiter(&self, waiter: super::ids::ThreadId) {
        self.signal_state
            .lock()
            .waiters
            .retain(|candidate| *candidate != waiter);
    }

    pub(crate) fn update_signals(&self, set: u64, clear: u64) {
        let waiters = {
            let mut state = self.signal_state.lock();
            let updated = (state.signals | set) & !clear;
            if updated == state.signals {
                return;
            }
            state.signals = updated;
            core::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            crate::task::wake_thread(waiter);
        }
    }
}

pub(crate) fn register_provider_object(object: &Arc<ProviderObject>) -> bool {
    let mut objects = PROVIDER_OBJECTS.lock();
    let key = object.key();
    if objects.get(&key).and_then(Weak::upgrade).is_some() {
        return false;
    }
    objects.insert(key, Arc::downgrade(object));
    object.registered.store(true, Ordering::Release);
    true
}

pub(crate) fn provider_object(
    endpoint_thread_id: u64,
    endpoint_slot: u16,
    endpoint_generation: u64,
    object_id: u64,
) -> Option<Arc<ProviderObject>> {
    PROVIDER_OBJECTS
        .lock()
        .get(&(
            endpoint_thread_id,
            endpoint_slot,
            endpoint_generation,
            object_id,
        ))
        .and_then(Weak::upgrade)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectHandle(u32);

impl ObjectHandle {
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if raw == 0 {
            None
        } else {
            Some(Self(raw))
        }
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HandleRights(u64);

impl HandleRights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const SEND: Self = Self(1 << 2);
    pub const RECEIVE: Self = Self(1 << 3);
    pub const WAIT: Self = Self(1 << 4);
    pub const SIGNAL: Self = Self(1 << 5);
    pub const MAP: Self = Self(1 << 6);
    pub const SEEK: Self = Self(1 << 7);
    pub const CONTROL: Self = Self(1 << 8);
    pub const DUPLICATE: Self = Self(1 << 62);
    pub const TRANSFER: Self = Self(1 << 63);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn from_bits(bits: u64) -> Option<Self> {
        if bits & !Self::ALL.bits() == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u64 {
        self.0
    }

    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const ALL: Self = Self(
        Self::READ.0
            | Self::WRITE.0
            | Self::SEND.0
            | Self::RECEIVE.0
            | Self::WAIT.0
            | Self::SIGNAL.0
            | Self::MAP.0
            | Self::SEEK.0
            | Self::CONTROL.0
            | Self::DUPLICATE.0
            | Self::TRANSFER.0,
    );
}

/// Kernel object identity stored behind a process-local handle.
///
/// Variants describe mechanism only. User-space policy and service names must
/// never be represented here.
#[derive(Clone)]
pub enum KernelObject {
    IpcEndpoint {
        thread_id: u64,
        slot: u16,
        generation: u64,
    },
    Event(u64),
    Process(Arc<ProcessObject>),
    Thread(super::ids::ThreadId),
    VmObject(Arc<crate::mem::vm_object::VmObject>),
    AddressSpace(Arc<crate::mem::address_space::AddressSpaceObject>),
    HandleSnapshot(Arc<super::handle_snapshot::HandleSnapshot>),
    File(Arc<FileHandle>),
    Provider(Arc<ProviderObject>),
}

impl KernelObject {
    /// Returns whether two handles name the same kernel object. This exposes
    /// no object identifier and therefore cannot be used to name an object
    /// that the caller does not already possess.
    pub(crate) fn is_same_object(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::IpcEndpoint {
                    thread_id: left_thread,
                    slot: left_slot,
                    generation: left_generation,
                },
                Self::IpcEndpoint {
                    thread_id: right_thread,
                    slot: right_slot,
                    generation: right_generation,
                },
            ) => {
                left_thread == right_thread
                    && left_slot == right_slot
                    && left_generation == right_generation
            }
            (Self::Event(left), Self::Event(right)) => left == right,
            (Self::Process(left), Self::Process(right)) => Arc::ptr_eq(left, right),
            (Self::Thread(left), Self::Thread(right)) => left == right,
            (Self::VmObject(left), Self::VmObject(right)) => Arc::ptr_eq(left, right),
            (Self::AddressSpace(left), Self::AddressSpace(right)) => Arc::ptr_eq(left, right),
            (Self::HandleSnapshot(left), Self::HandleSnapshot(right)) => Arc::ptr_eq(left, right),
            (Self::File(left), Self::File(right)) => Arc::ptr_eq(left, right),
            (Self::Provider(left), Self::Provider(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl core::fmt::Debug for KernelObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IpcEndpoint {
                thread_id,
                slot,
                generation,
            } => formatter
                .debug_struct("IpcEndpoint")
                .field("thread_id", thread_id)
                .field("slot", slot)
                .field("generation", generation)
                .finish(),
            Self::Event(id) => formatter.debug_tuple("Event").field(id).finish(),
            Self::Process(process) => formatter
                .debug_tuple("Process")
                .field(&process.id())
                .finish(),
            Self::Thread(thread) => formatter.debug_tuple("Thread").field(thread).finish(),
            Self::VmObject(id) => formatter.debug_tuple("VmObject").field(id).finish(),
            Self::AddressSpace(image) => formatter.debug_tuple("AddressSpace").field(image).finish(),
            Self::HandleSnapshot(snapshot) => formatter
                .debug_tuple("HandleSnapshot")
                .field(&snapshot.len())
                .finish(),
            Self::File(file) => formatter
                .debug_tuple("File")
                .field(&(Arc::as_ptr(file) as usize))
                .finish(),
            Self::Provider(object) => formatter.debug_tuple("Provider").field(object).finish(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ObjectHandleEntry {
    object: KernelObject,
    rights: HandleRights,
}

impl ObjectHandleEntry {
    pub const fn new(object: KernelObject, rights: HandleRights) -> Self {
        Self { object, rights }
    }

    pub const fn object(&self) -> &KernelObject {
        &self.object
    }

    pub const fn rights(&self) -> HandleRights {
        self.rights
    }

    pub(crate) fn restricted(&self, requested: HandleRights) -> Option<Self> {
        self.rights
            .contains(requested)
            .then(|| Self::new(self.object.clone(), requested))
    }
}

#[derive(Clone, Debug)]
pub struct ObjectHandleTable {
    entries: BTreeMap<ObjectHandle, ObjectHandleEntry>,
    next: u32,
}

impl ObjectHandleTable {
    pub fn new_boxed() -> Box<Self> {
        Box::new(Self {
            entries: BTreeMap::new(),
            next: 1,
        })
    }

    pub fn get(&self, handle: ObjectHandle) -> Option<ObjectHandleEntry> {
        self.entries.get(&handle).cloned()
    }

    /// Captures transferable references and all metadata under the caller's
    /// table lock. Closing/reusing a live slot cannot retarget these references.
    pub fn capture(&self) -> Result<super::handle_snapshot::HandleSnapshot, ()> {
        super::handle_snapshot::HandleSnapshot::capture(
            self.entries
                .iter()
                .map(|(handle, entry)| (*handle, entry.clone())),
        )
    }

    /// Metadata only: neither duplicates objects nor makes another table visible.
    pub fn describe(&self) -> Vec<mnu_abi::HandleInfo> {
        self.entries
            .iter()
            .map(|(handle, entry)| mnu_abi::HandleInfo {
                handle: handle.raw(),
                reserved: 0,
                rights: entry.rights().bits(),
            })
            .collect()
    }

    pub fn insert(&mut self, entry: ObjectHandleEntry) -> Option<ObjectHandle> {
        if self.entries.len() >= PROCESS_MAX_OBJECT_HANDLES {
            return None;
        }
        for _ in 0..PROCESS_MAX_OBJECT_HANDLES {
            let raw = self.next.clamp(1, PROCESS_MAX_OBJECT_HANDLES as u32);
            self.next = if raw == PROCESS_MAX_OBJECT_HANDLES as u32 {
                1
            } else {
                raw + 1
            };
            let handle = ObjectHandle(raw);
            if let alloc::collections::btree_map::Entry::Vacant(slot) = self.entries.entry(handle) {
                slot.insert(entry);
                return Some(handle);
            }
        }
        None
    }

    pub fn close(&mut self, handle: ObjectHandle) -> bool {
        self.entries.remove(&handle).is_some()
    }

    /// Installs an explicitly transferred object without replacing any entry.
    /// Only the receiving table is touched; this grants no capture authority.
    pub fn insert_at(&mut self, handle: ObjectHandle, entry: ObjectHandleEntry) -> bool {
        if handle.raw() > PROCESS_MAX_OBJECT_HANDLES as u32
            || self.entries.len() >= PROCESS_MAX_OBJECT_HANDLES
        {
            return false;
        }
        if let alloc::collections::btree_map::Entry::Vacant(slot) = self.entries.entry(handle) {
            slot.insert(entry);
            true
        } else {
            false
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(ObjectHandle) -> bool) {
        self.entries.retain(|handle, _| keep(*handle));
    }

    pub fn duplicate_restricted(
        &mut self,
        source: ObjectHandle,
        requested: HandleRights,
    ) -> Option<ObjectHandle> {
        let entry = self.get(source)?;
        if !entry.rights().contains(HandleRights::DUPLICATE) {
            return None;
        }
        self.insert(entry.restricted(requested)?)
    }

    /// Creates the entry installed in another process by an IPC or launch
    /// transfer. Installation itself is performed by the receiving process.
    pub fn export_restricted(
        &self,
        source: ObjectHandle,
        requested: HandleRights,
    ) -> Option<ObjectHandleEntry> {
        let entry = self.get(source)?;
        if !entry.rights().contains(HandleRights::TRANSFER) {
            return None;
        }
        entry.restricted(requested)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::task::{FileHandleCap, OpenFile};

    fn endpoint() -> KernelObject {
        KernelObject::IpcEndpoint {
            thread_id: 17,
            slot: 3,
            generation: 9,
        }
    }

    #[test]
    fn handles_are_process_local_and_zero_is_never_allocated() {
        let mut first = ObjectHandleTable::new_boxed();
        let mut second = ObjectHandleTable::new_boxed();
        let rights = HandleRights::SEND;
        let a = first
            .insert(ObjectHandleEntry::new(endpoint(), rights))
            .unwrap();
        let b = second
            .insert(ObjectHandleEntry::new(endpoint(), rights))
            .unwrap();
        assert_ne!(a.raw(), 0);
        assert_eq!(a, b);
        assert!(first.get(a).is_some());
        assert!(second.get(b).is_some());
    }

    #[test]
    fn duplicate_and_transfer_can_only_reduce_rights() {
        let mut table = ObjectHandleTable::new_boxed();
        let source_rights = HandleRights::SEND
            .union(HandleRights::DUPLICATE)
            .union(HandleRights::TRANSFER);
        let source = table
            .insert(ObjectHandleEntry::new(endpoint(), source_rights))
            .unwrap();

        let duplicate = table
            .duplicate_restricted(source, HandleRights::SEND)
            .unwrap();
        assert_eq!(table.get(duplicate).unwrap().rights(), HandleRights::SEND);
        assert!(
            table
                .get(source)
                .unwrap()
                .object()
                .is_same_object(table.get(duplicate).unwrap().object())
        );
        assert!(table
            .duplicate_restricted(source, HandleRights::RECEIVE)
            .is_none());
        assert_eq!(
            table
                .export_restricted(source, HandleRights::SEND)
                .unwrap()
                .rights(),
            HandleRights::SEND
        );
        assert!(table
            .export_restricted(source, HandleRights::RECEIVE)
            .is_none());
    }

    #[test]
    fn transfer_requires_explicit_transfer_right() {
        let mut table = ObjectHandleTable::new_boxed();
        let source = table
            .insert(ObjectHandleEntry::new(endpoint(), HandleRights::SEND))
            .unwrap();
        assert!(table
            .export_restricted(source, HandleRights::SEND)
            .is_none());
    }

    #[test]
    fn duplicated_file_handles_share_the_same_open_file_description() {
        let file = Arc::new(FileHandle::new(
            OpenFile {
                pipe_id: None,
                pipe_write: false,
                io_options: 0,
            },
            FileHandleCap::READ,
        ));
        let mut table = ObjectHandleTable::new_boxed();
        let source = table
            .insert(ObjectHandleEntry::new(
                KernelObject::File(file.clone()),
                HandleRights::READ
                    .union(HandleRights::DUPLICATE)
                    .union(HandleRights::TRANSFER),
            ))
            .unwrap();
        let duplicate = table
            .duplicate_restricted(source, HandleRights::READ)
            .unwrap();

        let source = table.get(source).unwrap();
        let duplicate = table.get(duplicate).unwrap();
        let (KernelObject::File(source), KernelObject::File(duplicate)) =
            (source.object(), duplicate.object())
        else {
            panic!("file object changed type during duplication");
        };
        assert!(Arc::ptr_eq(source, duplicate));
    }

    #[test]
    fn provider_objects_are_opaque_and_share_identity_across_duplicates() {
        let provider = Arc::new(ProviderObject::new(31, 4, 8, 99).unwrap());
        let mut table = ObjectHandleTable::new_boxed();
        let source = table
            .insert(ObjectHandleEntry::new(
                KernelObject::Provider(provider),
                HandleRights::READ
                    .union(HandleRights::DUPLICATE)
                    .union(HandleRights::TRANSFER),
            ))
            .unwrap();
        let duplicate = table
            .duplicate_restricted(source, HandleRights::READ)
            .unwrap();
        let source = table.get(source).unwrap();
        let duplicate = table.get(duplicate).unwrap();
        let (KernelObject::Provider(source), KernelObject::Provider(duplicate)) =
            (source.object(), duplicate.object())
        else {
            panic!("provider object changed type during duplication");
        };
        assert!(Arc::ptr_eq(source, duplicate));
        assert_eq!(source.object_id, 99);
        assert_eq!(source.io_options(), 0);
        source.set_io_options(mnu_abi::HANDLE_OPTION_NONBLOCKING);
        assert_eq!(duplicate.io_options(), mnu_abi::HANDLE_OPTION_NONBLOCKING);
    }

    #[test]
    fn provider_readiness_signals_are_generic_and_level_triggered() {
        let provider = ProviderObject::new(41, 5, 9, 101).unwrap();

        assert_eq!(provider.signals(), 0);
        provider.update_signals(
            mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_IDLE,
            0,
        );
        assert_eq!(
            provider.signals(),
            mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_WRITABLE
                | mnu_abi::HANDLE_SIGNAL_IDLE
        );
        provider.update_signals(
            mnu_abi::HANDLE_SIGNAL_PEER_CLOSED,
            mnu_abi::HANDLE_SIGNAL_WRITABLE,
        );
        assert_eq!(
            provider.signals(),
            mnu_abi::HANDLE_SIGNAL_READABLE
                | mnu_abi::HANDLE_SIGNAL_PEER_CLOSED
                | mnu_abi::HANDLE_SIGNAL_IDLE
        );
    }
}
