use crate::capability::Capability;
use crate::syscall::types::{EACCES, EFAULT, EINVAL, ENOMEM, SUCCESS};
use crate::task::{DmaBuffer, ProcessId};
use core::sync::atomic::{AtomicU64, Ordering};
use mnu_abi::DmaAllocation;
use x86_64::structures::paging::PhysFrame;
use x86_64::PhysAddr;

static NEXT_DMA_HANDLE: AtomicU64 = AtomicU64::new(1);
const DMA_VA_BASE_MIN: u64 = 0x0000_7000_0000_0000;
const DMA_VA_ASLR_MAX_PAGES: u64 = 0x20_000;

fn caller_has_dma_capability() -> bool {
    crate::syscall::security::caller_has_any_capability(&[Capability::DmaAllocate])
}

fn current_process() -> Option<(ProcessId, u64)> {
    let tid = crate::task::current_thread_id()?;
    let pid = crate::task::with_thread(tid, |t| t.process_id())?;
    let pt = crate::task::with_process(pid, |p| p.page_table()).flatten()?;
    Some((pid, pt))
}

fn page_align_up(addr: u64) -> Option<u64> {
    addr.checked_add(4095).map(|v| v & !4095)
}

#[inline]
fn aslr_mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn randomized_dma_base(pid: ProcessId) -> u64 {
    let seed = crate::cpu::boot_entropy_u64()
        ^ crate::interrupt::timer::get_ticks().rotate_left(11)
        ^ pid.as_u64().rotate_left(19)
        ^ DMA_VA_BASE_MIN.rotate_left(7);
    DMA_VA_BASE_MIN.saturating_add((aslr_mix64(seed) % DMA_VA_ASLR_MAX_PAGES) * 4096)
}

fn allocate_dma_virtual_range(pid: ProcessId, size: u64) -> Result<(u64, u64), u64> {
    crate::task::with_process_mut(pid, |process| {
        if process.dma_end() == 0 {
            let base = randomized_dma_base(pid);
            process.set_dma_start(base);
            process.set_dma_end(base);
        }
        let old_dma_end = process.dma_end();
        let map_start = page_align_up(old_dma_end).ok_or(EINVAL)?;
        let new_heap_end = map_start.checked_add(size).ok_or(EINVAL)?;
        process.set_dma_end(new_heap_end);
        Ok((map_start, old_dma_end))
    })
    .unwrap_or(Err(ENOMEM))
}

pub fn alloc(length: u64, out_ptr: u64) -> u64 {
    if !caller_has_dma_capability() {
        return EACCES;
    }
    if length == 0 || out_ptr == 0 {
        return EINVAL;
    }
    if !crate::syscall::validate_user_ptr(out_ptr, core::mem::size_of::<DmaAllocation>() as u64) {
        return EFAULT;
    }

    let size = match page_align_up(length) {
        Some(v) if v > 0 => v,
        _ => return EINVAL,
    };
    let page_count = (size / 4096) as usize;
    let (pid, pt_phys) = match current_process() {
        Some(v) => v,
        None => return ENOMEM,
    };
    let first_frame = match crate::mem::frame::allocate_contiguous_frames(page_count) {
        Ok(frame) => frame,
        Err(_) => return ENOMEM,
    };
    let phys_start = first_frame.start_address().as_u64();
    let handle = NEXT_DMA_HANDLE.fetch_add(1, Ordering::Relaxed);

    let (virt_start, old_dma_end) = match allocate_dma_virtual_range(pid, size) {
        Ok(v) => v,
        Err(errno) => {
            for idx in 0..page_count {
                let frame = PhysFrame::containing_address(PhysAddr::new(
                    phys_start + (idx as u64) * 4096,
                ));
                let _ = crate::mem::frame::deallocate_frame(frame);
            }
            return errno;
        }
    };

    let buffer = DmaBuffer::new(handle, virt_start, size, phys_start, page_count);
    let reserved = crate::task::with_process_mut(pid, |process| process.add_dma_buffer(buffer.clone()))
        .unwrap_or(false);
    if !reserved {
        let _ = crate::task::with_process_mut(pid, |process| process.set_dma_end(old_dma_end));
        for idx in 0..page_count {
            let frame = PhysFrame::containing_address(PhysAddr::new(
                phys_start + (idx as u64) * 4096,
            ));
            let _ = crate::mem::frame::deallocate_frame(frame);
        }
        return EINVAL;
    }

    let mut mapped_pages = 0usize;
    for idx in 0..page_count {
        let virt = virt_start + (idx as u64) * 4096;
        let phys = phys_start + (idx as u64) * 4096;
        if crate::mem::paging::map_page_in_table(pt_phys, virt, phys, true, true).is_err() {
            let rollback_len = (mapped_pages as u64) * 4096;
            if rollback_len != 0 {
                let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
                    pt_phys,
                    virt_start,
                    rollback_len,
                );
            }
            let _ = crate::task::with_process_mut(pid, |process| {
                let _ = process.remove_dma_buffer(handle);
                process.set_dma_end(old_dma_end);
            });
            for free_idx in 0..page_count {
                let frame = PhysFrame::containing_address(PhysAddr::new(
                    phys_start + (free_idx as u64) * 4096,
                ));
                let _ = crate::mem::frame::deallocate_frame(frame);
            }
            return ENOMEM;
        }
        mapped_pages += 1;
    }

    let info = DmaAllocation {
        handle,
        virt_addr: virt_start,
        phys_addr: phys_start,
        len: size,
    };
    let info_bytes = unsafe {
        core::slice::from_raw_parts(
            (&info as *const DmaAllocation).cast::<u8>(),
            core::mem::size_of::<DmaAllocation>(),
        )
    };
    if crate::syscall::copy_to_user(out_ptr, info_bytes).is_err() {
        let _ = free(handle);
        return EFAULT;
    }

    SUCCESS
}

pub fn free(handle: u64) -> u64 {
    if !caller_has_dma_capability() {
        return EACCES;
    }
    if handle == 0 {
        return EINVAL;
    }
    let (pid, pt_phys) = match current_process() {
        Some(v) => v,
        None => return ENOMEM,
    };
    let buffer = match crate::task::with_process_mut(pid, |process| process.remove_dma_buffer(handle)) {
        Some(Some(buffer)) => buffer,
        Some(None) => return EINVAL,
        None => return ENOMEM,
    };
    let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
        pt_phys,
        buffer.virt_start(),
        buffer.len(),
    );
    for idx in 0..buffer.page_count() {
        let frame = PhysFrame::containing_address(PhysAddr::new(
            buffer.phys_start() + (idx as u64) * 4096,
        ));
        let _ = crate::mem::frame::deallocate_frame(frame);
    }
    SUCCESS
}
