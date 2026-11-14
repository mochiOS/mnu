//! Scoped authority for edits to a retained, exclusively owned page-table root.
use super::{Kernel, Memory, Result};
use core::marker::PhantomData;

pub(crate) struct TableEdit<'owner> {
    table: u64,
    _owner: PhantomData<&'owner mut ()>,
    _not_send: PhantomData<*mut ()>,
}

impl<'owner> TableEdit<'owner> {
    /// # Safety
    /// `owner` must retain this root AND exclude all hierarchy/PTE writers for
    /// the borrow: either an unpublished physical root owner, or the VM table
    /// lock. A physical address, root pin alone, or caller-supplied value is not
    /// sufficient. Do not keep this authority after publishing an owned image.
    pub(crate) unsafe fn new<T: ?Sized>(table: u64, _owner: &'owner mut T) -> Result<Self> {
        if table == 0 || table & 4095 != 0 {
            return Err(Kernel::Memory(Memory::InvalidAddress));
        }
        Ok(Self {
            table,
            _owner: PhantomData,
            _not_send: PhantomData,
        })
    }
    pub(crate) fn table(&self) -> u64 {
        self.table
    }
    pub(crate) fn map_segment(
        &mut self,
        address: u64,
        file_size: u64,
        memory_size: u64,
        source: &[u8],
        writable: bool,
        executable: bool,
    ) -> Result<()> {
        // SAFETY: construction binds this edit to retained root/exclusion.
        unsafe {
            super::map_and_copy_segment_to(
                self.table,
                address,
                file_size,
                memory_size,
                source,
                writable,
                executable,
            )
        }
    }
    pub(crate) fn map_frame(
        &mut self,
        address: u64,
        physical: u64,
        writable: bool,
        user_accessible: bool,
    ) -> Result<()> {
        // SAFETY: the same root/exclusion proof covers hierarchy allocation.
        unsafe {
            super::map_page_in_table(self.table, address, physical, writable, user_accessible)
        }
    }
}
