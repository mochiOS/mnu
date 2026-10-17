//! Owned backing ranges, captured before external writeback begins. There are
//! no user virtual addresses to reinterpret after unmap, replacement or exit.
use alloc::vec::Vec;

pub(crate) struct Batch<T> {
    work: Vec<((T, u64), u64)>,
}

impl<T> Batch<T> {
    pub(crate) fn new(work: Vec<((T, u64), u64)>) -> Self {
        Self { work }
    }

    /// A failure retains every owned target in this batch. Execution may be
    /// queued by an owner, but this method itself makes no scheduling promise.
    pub(crate) fn execute(
        &self,
        mut flush: impl FnMut(&T, u64, u64) -> Result<(), u64>,
    ) -> Result<(), u64> {
        for ((target, offset), length) in &self.work {
            flush(target, *offset, *length)?;
        }
        Ok(())
    }
}
