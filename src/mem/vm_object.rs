//! VM objects and a bounded vnode page cache.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::interrupt::spinlock::SpinLock;
use crate::vfs::{InodeId, MountId, Vnode};

pub const PAGE_BYTES: usize = 4096;
const MAX_CACHED_PAGES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageKey {
    mount_id: MountId,
    inode_id: InodeId,
    page_index: u64,
}

struct CachedPage {
    key: PageKey,
    bytes: Arc<[u8; PAGE_BYTES]>,
}

static PAGE_CACHE: SpinLock<Vec<CachedPage>> = SpinLock::new(Vec::new());

#[derive(Clone)]
pub struct VmObject {
    vnode: Arc<Vnode>,
}

impl VmObject {
    pub fn file(vnode: Arc<Vnode>) -> Self {
        Self { vnode }
    }

    pub fn vnode(&self) -> &Arc<Vnode> {
        &self.vnode
    }

    pub fn page(&self, page_index: u64) -> Result<Arc<[u8; PAGE_BYTES]>, u64> {
        let key = PageKey {
            mount_id: self.vnode.inode.mount_id,
            inode_id: self.vnode.inode.inode_id,
            page_index,
        };
        if let Some(bytes) = cached_page(key) {
            return Ok(bytes);
        }

        let offset = page_index
            .checked_mul(PAGE_BYTES as u64)
            .ok_or(crate::syscall::EINVAL)?;
        let mut page = [0u8; PAGE_BYTES];
        let _ = self.vnode.read_at(offset, &mut page)?;
        let bytes = Arc::new(page);

        let mut cache = PAGE_CACHE.lock();
        if let Some(existing) = cache.iter().find(|entry| entry.key == key) {
            return Ok(existing.bytes.clone());
        }
        if cache.len() == MAX_CACHED_PAGES {
            cache.remove(0);
        }
        cache.push(CachedPage {
            key,
            bytes: bytes.clone(),
        });
        Ok(bytes)
    }

    pub fn invalidate(&self) {
        invalidate_inode(self.vnode.inode.mount_id, self.vnode.inode.inode_id);
    }

    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let written = self.vnode.write_at(offset, input)?;
        self.invalidate();
        Ok(written)
    }
}

impl core::fmt::Debug for VmObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VmObject")
            .field("mount_id", &self.vnode.inode.mount_id)
            .field("inode_id", &self.vnode.inode.inode_id)
            .finish()
    }
}

fn cached_page(key: PageKey) -> Option<Arc<[u8; PAGE_BYTES]>> {
    PAGE_CACHE
        .lock()
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.bytes.clone())
}

pub fn invalidate_inode(mount_id: MountId, inode_id: InodeId) {
    PAGE_CACHE
        .lock()
        .retain(|entry| entry.key.mount_id != mount_id || entry.key.inode_id != inode_id);
}
