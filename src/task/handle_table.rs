use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::fd_table::FileHandle;

pub const PROCESS_MAX_OBJECT_HANDLES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderObject {
    pub endpoint_thread_id: u64,
    pub endpoint_slot: u16,
    pub endpoint_generation: u64,
    pub object_id: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct ProviderRelease {
    pub endpoint_thread_id: u64,
    pub endpoint_slot: u16,
    pub endpoint_generation: u64,
    pub object_id: u64,
}

static PENDING_PROVIDER_RELEASES: crate::interrupt::spinlock::SpinLock<Vec<ProviderRelease>> =
    crate::interrupt::spinlock::SpinLock::new(Vec::new());

pub(crate) fn take_provider_releases() -> Vec<ProviderRelease> {
    core::mem::take(&mut *PENDING_PROVIDER_RELEASES.lock())
}

pub(crate) fn requeue_provider_releases(releases: &mut Vec<ProviderRelease>) {
    if releases.is_empty() {
        return;
    }
    PENDING_PROVIDER_RELEASES.lock().append(releases);
}

impl Drop for ProviderObject {
    fn drop(&mut self) {
        PENDING_PROVIDER_RELEASES.lock().push(ProviderRelease {
            endpoint_thread_id: self.endpoint_thread_id,
            endpoint_slot: self.endpoint_slot,
            endpoint_generation: self.endpoint_generation,
            object_id: self.object_id,
        });
    }
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
    Process(u64),
    VmObject(u64),
    File(Arc<FileHandle>),
    Provider(Arc<ProviderObject>),
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
            Self::Process(id) => formatter.debug_tuple("Process").field(id).finish(),
            Self::VmObject(id) => formatter.debug_tuple("VmObject").field(id).finish(),
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

    fn restricted(&self, requested: HandleRights) -> Option<Self> {
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
                data: Box::new([]),
                pos: 0,
                vnode: None,
                is_remote: false,
                fd_remote: 0,
                pipe_id: None,
                pipe_write: false,
                open_flags: 0,
            },
            FileHandleCap::READ.union(FileHandleCap::TRANSFER),
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
        let provider = Arc::new(ProviderObject {
            endpoint_thread_id: 31,
            endpoint_slot: 4,
            endpoint_generation: 8,
            object_id: 99,
        });
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
    }
}
