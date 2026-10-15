use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use super::shared_pages::{PageError, ResizeError, SharedPages, SizeError};
use crate::interrupt::spinlock::SpinLock;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
const PAGE_BYTES: u64 = super::vm_object::PAGE_BYTES as u64;

/// Owns anonymous backing storage, not another process's virtual memory.
pub struct SharedMemory {
    id: u64,
    generation: AtomicU64,
    pages: SpinLock<SharedPages<OwnedFrame>>,
}

struct OwnedFrame(u64);

impl Drop for OwnedFrame {
    fn drop(&mut self) {
        super::paging::release_user_frame(self.0);
    }
}

impl SharedMemory {
    pub fn new(length: u64, maximum_pages: u64) -> Result<Self, u64> {
        let pages = SharedPages::new(length, PAGE_BYTES, maximum_pages);
        Self::from_pages(pages)
    }

    /// Byte extent constructor for explicitly resizable native RAM objects.
    pub(crate) fn new_resizable(length: u64, maximum_pages: u64) -> Result<Self, u64> {
        Self::from_pages(SharedPages::new_bytes(length, PAGE_BYTES, maximum_pages))
    }

    fn from_pages(pages: Result<SharedPages<OwnedFrame>, SizeError>) -> Result<Self, u64> {
        let pages = pages.map_err(|error| match error {
            SizeError::Invalid => crate::syscall::EINVAL,
            SizeError::LimitExceeded => crate::syscall::ENOMEM,
        })?;
        let id = NEXT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| crate::syscall::ENOMEM)?;
        Ok(Self {
            id,
            generation: AtomicU64::new(0),
            pages: SpinLock::new(pages),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn length(&self) -> u64 {
        self.pages.lock().length()
    }
    pub fn contains_range(&self, offset: u64, length: u64) -> bool {
        self.pages.lock().contains_range(offset, length)
    }

    fn page(&self, index: u64) -> Result<(Arc<OwnedFrame>, u64), u64> {
        let mut pages = self.pages.lock();
        let page = Self::populate(&mut pages, index)?;
        Ok((page, self.generation.load(Ordering::Relaxed)))
    }

    fn populate(pages: &mut SharedPages<OwnedFrame>, index: u64) -> Result<Arc<OwnedFrame>, u64> {
        pages
            .page_or_try_insert(index, || {
                super::frame::allocate_zeroed_frame()
                    .map(|frame| OwnedFrame(frame.start_address().as_u64()))
                    .map_err(|_| crate::syscall::ENOMEM)
            })
            .map_err(|error| match error {
                PageError::OutOfBounds => crate::syscall::EINVAL,
                PageError::Allocation(error) => error,
            })
    }

    /// Retains a frame for the caller; release it with `release_user_frame`.
    pub fn retain_page(&self, index: u64) -> Result<u64, u64> {
        self.prepare_page(index).map(|(frame, _)| frame)
    }

    /// The retained frame and generation come from one serialized population.
    pub(crate) fn prepare_page(&self, index: u64) -> Result<(u64, u64), u64> {
        let (page, generation) = self.page(index)?;
        super::paging::retain_shared_user_frame(page.0).map_err(|_| crate::syscall::ENOMEM)?;
        Ok((page.0, generation))
    }

    /// Capture the serialized epoch before loading private page bytes.
    pub(crate) fn generation(&self) -> u64 {
        let _pages = self.pages.lock();
        self.generation.load(Ordering::Relaxed)
    }

    /// Keep size/epoch stable through the final PTE installation. This prevents
    /// an old prepared page from being installed after shrink and regrowth.
    pub(crate) fn with_generation<T>(
        &self,
        generation: u64,
        install: impl FnOnce() -> Result<T, u64>,
    ) -> Result<T, u64> {
        let _pages = self.pages.lock();
        if self.generation.load(Ordering::Relaxed) != generation {
            return Err(crate::syscall::EAGAIN);
        }
        install()
    }

    /// The VM coordinator must exclude mapping changes, revoke every supplied
    /// range (including a growth boundary) and acknowledge remote TLBs before
    /// returning. Boundary pointer validation precedes revocation and mutation.
    pub(crate) fn resize_with(
        &self,
        length: u64,
        revoke: impl FnOnce(u64, u64) -> Result<(), u64>,
    ) -> Result<(), u64> {
        self.resize_transaction(length, |start, end, commit| {
            revoke(start, end)?;
            Ok(commit.commit())
        })
    }

    pub(crate) fn resize_transaction(
        &self,
        length: u64,
        coordinate: impl for<'a> FnOnce(
            u64,
            u64,
            super::shared_pages::ResizeCommit<'a>,
        )
            -> Result<super::shared_pages::ResizeCommitted<'a>, u64>,
    ) -> Result<(), u64> {
        let mut pages = self.pages.lock();
        if pages.length() == length {
            return Ok(());
        }
        let next = self
            .generation
            .load(Ordering::Relaxed)
            .checked_add(1)
            .ok_or(crate::syscall::ENOMEM)?;
        pages
            .resize_bytes_transaction(
                length,
                |page, range| {
                    let base = super::paging::physical_memory_offset()
                        .and_then(|offset| offset.checked_add(page.0))
                        .ok_or(crate::syscall::EIO)?;
                    let start = base.checked_add(range.start).ok_or(crate::syscall::EIO)?;
                    base.checked_add(range.end).ok_or(crate::syscall::EIO)?;
                    Ok((start, range.end - range.start))
                },
                coordinate,
                |_, (start, count)| {
                    // No fallible operations after revocation. Never form a
                    // reference to physical bytes also mapped by another CPU.
                    for offset in 0..count {
                        unsafe { core::ptr::write_volatile((start + offset) as *mut u8, 0) };
                    }
                },
            )
            .map_err(|error| match error {
                ResizeError::Size(SizeError::Invalid) => crate::syscall::EINVAL,
                ResizeError::Size(SizeError::LimitExceeded) => crate::syscall::ENOMEM,
                ResizeError::Revocation(error) => error,
                ResizeError::Preparation(error) => error,
            })?;
        self.generation.store(next, Ordering::Release);
        Ok(())
    }

    pub fn read_at(&self, offset: u64, output: &mut [u8]) -> Result<usize, u64> {
        let mut pages = self.pages.lock();
        let backing_length = pages.length();
        if offset > backing_length {
            return Err(crate::syscall::EINVAL);
        }
        let length = output.len().min((backing_length - offset) as usize);
        Self::copy(&mut pages, offset, length, |pointer, done, count| {
            for index in 0..count {
                // Mapped users may modify the bytes; never form a Rust reference
                // to storage owned concurrently by a different address space.
                output[done + index] = unsafe { core::ptr::read_volatile(pointer.add(index)) };
            }
        })?;
        Ok(length)
    }

    pub fn write_at(&self, offset: u64, input: &[u8]) -> Result<usize, u64> {
        let mut pages = self.pages.lock();
        if !pages.contains_range(offset, input.len() as u64) {
            return Err(crate::syscall::EINVAL);
        }
        Self::copy(&mut pages, offset, input.len(), |pointer, done, count| {
            for index in 0..count {
                unsafe {
                    core::ptr::write_volatile(pointer.add(index), input[done + index]);
                }
            }
        })?;
        Ok(input.len())
    }

    fn copy(
        pages: &mut SharedPages<OwnedFrame>,
        offset: u64,
        length: usize,
        mut copy: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), u64> {
        let physical_offset = super::paging::physical_memory_offset().ok_or(crate::syscall::EIO)?;
        let mut done = 0;
        while done < length {
            let current = offset + done as u64;
            let page = Self::populate(pages, current / PAGE_BYTES)?;
            let within = (current % PAGE_BYTES) as usize;
            let count = (length - done).min(PAGE_BYTES as usize - within);
            let address = physical_offset
                .checked_add(page.0)
                .and_then(|address| address.checked_add(within as u64))
                .ok_or(crate::syscall::EIO)?;
            copy(address as *mut u8, done, count);
            done += count;
        }
        Ok(())
    }
}
