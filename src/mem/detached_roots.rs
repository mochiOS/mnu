//! Owned, not-yet-published VM roots. Weak discovery does not extend lifetime;
//! snapshot pins retain physical tables even across publication and retirement.
use super::vm_object::ObjectKey;
use crate::interrupt::spinlock::SpinLock;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

static ROOTS: SpinLock<Vec<Weak<Root>>> = SpinLock::new(Vec::new());
const MAX_ROOTS: usize = 65536;

pub(crate) struct Mapping {
    pub identity: ObjectKey,
    pub start: u64,
    pub length: u64,
    pub offset: u64,
}

pub(crate) struct Root {
    table: u64,
    _lifetime: Option<super::root_lifetime::Pin>,
    mappings: Vec<Mapping>,
    published: AtomicBool,
}

impl Root {
    /// Takes physical-table ownership immediately, including failure paths.
    /// Called under the mapping/process lock after cloning completes.
    pub(crate) fn new(table: u64, regions: &[crate::task::MemoryRegion]) -> Result<Arc<Self>, ()> {
        let mut root = Self {
            table,
            _lifetime: None,
            mappings: Vec::new(),
            published: AtomicBool::new(false),
        };
        root._lifetime = Some(super::root_lifetime_native::pin(table)?);
        for region in regions {
            if let Some(identity) = region
                .backing()
                .file_object()
                .map(|object| object.object_key())
            {
                root.mappings.try_reserve(1).map_err(|_| ())?;
                root.mappings.push(Mapping {
                    identity,
                    start: region.start(),
                    length: region.len(),
                    offset: region.backing().file_offset(),
                });
            }
        }
        let root = Arc::new(root);
        let mut roots = ROOTS.lock();
        roots.retain(|root| root.strong_count() != 0);
        if roots.len() >= MAX_ROOTS {
            return Err(());
        }
        roots.try_reserve(1).map_err(|_| ())?;
        roots.push(Arc::downgrade(&root));
        Ok(root)
    }

    pub(crate) fn table(&self) -> u64 {
        self.table
    }
    pub(crate) fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }
    pub(crate) fn published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    /// The process-table lock makes ownership handoff and process insertion
    /// atomic relative to resize. The creator's guard owns failure cleanup
    /// after this point; the published process owns successful lifetime.
    pub(crate) fn publish(&self) {
        self.published.store(true, Ordering::Release);
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if !self.published() {
            if let Err(error) = super::paging::destroy_user_page_table(self.table) {
                crate::warn!("Failed to release unpublished VM root: {:?}", error);
            }
        }
    }
}

/// Caller holds the mapping/process lock during discovery, mapping inspection
/// and revocation. Pins may outlive that lock for physical lifetime only: they
/// do not keep mapping records or PTE contents unchanged after publication.
/// No process IDs, descriptors, endpoints or names are used for discovery.
pub(crate) fn snapshot() -> Result<Vec<Arc<Root>>, ()> {
    let mut roots = ROOTS.lock();
    roots.retain(|root| root.strong_count() != 0);
    let mut pins = Vec::new();
    pins.try_reserve_exact(roots.len()).map_err(|_| ())?;
    for root in roots.iter().filter_map(Weak::upgrade) {
        if !root.published() {
            pins.push(root);
        }
    }
    Ok(pins)
}
