//! Detached VM images with immutable origin ceilings, not authority grants.

use alloc::vec::Vec;

use crate::interrupt::spinlock::SpinLock;
use crate::task::{MemoryRegion, Process};

#[derive(Debug, PartialEq, Eq)]
pub enum ConsumeError {
    Consumed,
    Authorization,
    Context,
}

/// All duplicate and transferred Handles share this one-shot ownership cell.
/// A failed validation leaves the image available; a successful take disarms
/// every alias before any execution container is published.
pub struct AddressSpaceObject {
    image: SpinLock<Option<AddressSpaceImage>>,
}

impl AddressSpaceObject {
    pub fn new(image: AddressSpaceImage) -> Self {
        Self {
            image: SpinLock::new(Some(image)),
        }
    }

    pub fn consume(
        &self,
        authorization: &crate::task::process::PendingExecSecurity,
        context: &mnu_abi::ThreadCreateContext,
    ) -> Result<AddressSpaceImage, ConsumeError> {
        let mut slot = self.image.lock();
        let image = slot.as_ref().ok_or(ConsumeError::Consumed)?;
        if !image.permits(authorization) {
            return Err(ConsumeError::Authorization);
        }
        let table = image.table.ok_or(ConsumeError::Consumed)?;
        if !super::paging::is_user_initial_context_in_table(table, context) {
            return Err(ConsumeError::Context);
        }
        slot.take().ok_or(ConsumeError::Consumed)
    }
}

impl core::fmt::Debug for AddressSpaceObject {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AddressSpaceObject")
            .finish_non_exhaustive()
    }
}

pub enum CloneError {
    MissingPageTable,
    BorrowedMapping,
    Allocation,
}

/// Captured while the source's execution is quiescent. The caller must keep it
/// quiescent until cloning completes; remote TLB invalidation is not available.
pub struct CloneSource {
    table: u64,
    regions: Vec<MemoryRegion>,
    excluded: Vec<(u64, u64)>,
    heap_start: u64,
    heap_end: u64,
    ipc_mapping_end: u64,
    stack_bottom: u64,
    stack_top: u64,
    origin: Option<crate::task::image_origin::ImageOrigin>,
}

impl CloneSource {
    pub fn capture(process: &Process) -> Result<Self, CloneError> {
        if process.has_mmio_mappings() {
            return Err(CloneError::BorrowedMapping);
        }
        let table = process.page_table().ok_or(CloneError::MissingPageTable)?;
        let mut excluded = Vec::new();
        for buffer in process.dma_buffers() {
            let end = buffer.end().ok_or(CloneError::BorrowedMapping)?;
            excluded.push((buffer.virt_start(), end));
        }
        Ok(Self {
            table,
            regions: process.memory_regions().to_vec(),
            excluded,
            heap_start: process.heap_start(),
            heap_end: process.heap_end(),
            ipc_mapping_end: process.ipc_mapping_end(),
            stack_bottom: process.stack_bottom(),
            stack_top: process.stack_top(),
            origin: crate::task::image_origin::ImageOrigin::capture(process),
        })
    }

    pub fn clone_image(self) -> Result<AddressSpaceImage, CloneError> {
        use super::paging::ForkPagePolicy;
        let table = super::paging::clone_user_page_table(self.table, |address| {
            if self
                .excluded
                .iter()
                .any(|&(start, end)| address >= start && address < end)
            {
                return ForkPagePolicy::Exclude;
            }
            match self.regions.iter().find(|region| region.contains(address)) {
                Some(region) if region.is_shared() => ForkPagePolicy::Shared,
                Some(_) => ForkPagePolicy::PrivateWritable,
                None => ForkPagePolicy::Private,
            }
        })
        .map_err(|_| CloneError::Allocation)?;
        Ok(AddressSpaceImage {
            table: Some(table),
            regions: self.regions,
            heap_start: self.heap_start,
            heap_end: self.heap_end,
            ipc_mapping_end: self.ipc_mapping_end,
            stack_bottom: self.stack_bottom,
            stack_top: self.stack_top,
            origin: self.origin,
        })
    }
}

/// Owns the detached page table and backing-object references. Dropping the
/// final Handle releases them even if no process was ever created from it.
pub struct AddressSpaceImage {
    table: Option<u64>,
    regions: Vec<MemoryRegion>,
    heap_start: u64,
    heap_end: u64,
    ipc_mapping_end: u64,
    stack_bottom: u64,
    stack_top: u64,
    origin: Option<crate::task::image_origin::ImageOrigin>,
}

impl AddressSpaceImage {
    /// An unmeasured or anonymous VM image cannot stand in for an authorized
    /// executable. The caller must still validate the authorization's owner
    /// and consume it through the existing native creation path.
    pub fn permits(&self, authorization: &crate::task::process::PendingExecSecurity) -> bool {
        self.origin
            .as_ref()
            .is_some_and(|origin| origin.permits(authorization))
    }

    /// Moves ownership into an empty, unpublished execution container. Existing
    /// address spaces must not be replaced implicitly by this operation.
    pub fn install(mut self, process: &mut Process) -> Result<(), Self> {
        if process.page_table().is_some() {
            return Err(self);
        }
        let Some(table) = self.table.take() else {
            return Err(self);
        };
        process.set_page_table(table);
        process.set_memory_regions(core::mem::take(&mut self.regions));
        process.set_heap_start(self.heap_start);
        process.set_heap_end(self.heap_end);
        process.set_ipc_mapping_end(self.ipc_mapping_end);
        process.set_stack_bottom(self.stack_bottom);
        process.set_stack_top(self.stack_top);
        Ok(())
    }
}

impl core::fmt::Debug for AddressSpaceImage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AddressSpaceImage")
            .finish_non_exhaustive()
    }
}

impl Drop for AddressSpaceImage {
    fn drop(&mut self) {
        if let Some(table) = self.table {
            if let Err(error) = super::paging::destroy_user_page_table(table) {
                crate::warn!("Failed to release detached address space: {:?}", error);
            }
        }
    }
}
