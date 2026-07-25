extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{Ordering, fence};

use super::dma::DmaMemory;
use super::error::{VirtioError, VirtioResult};

const DESCRIPTOR_SIZE: usize = 16;
const USED_ELEMENT_SIZE: usize = 8;
const DESCRIPTOR_F_NEXT: u16 = 1;
const DESCRIPTOR_F_WRITE: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub address: u64,
    pub length: u32,
    pub device_writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsedDescriptor {
    pub head: u16,
    pub written: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtqueueLayout {
    pub descriptor_offset: usize,
    pub available_offset: usize,
    pub used_offset: usize,
    pub total_size: usize,
}

impl VirtqueueLayout {
    pub fn calculate(size: u16) -> VirtioResult<Self> {
        if size < 2 || !size.is_power_of_two() {
            return Err(VirtioError::InvalidQueueSize);
        }
        let count = usize::from(size);
        let descriptor_bytes = count
            .checked_mul(DESCRIPTOR_SIZE)
            .ok_or(VirtioError::ArithmeticOverflow)?;
        let available_bytes = count
            .checked_mul(2)
            .and_then(|ring| ring.checked_add(6))
            .ok_or(VirtioError::ArithmeticOverflow)?;
        let used_offset = align_up(
            descriptor_bytes
                .checked_add(available_bytes)
                .ok_or(VirtioError::ArithmeticOverflow)?,
            4,
        )?;
        let used_bytes = count
            .checked_mul(USED_ELEMENT_SIZE)
            .and_then(|ring| ring.checked_add(6))
            .ok_or(VirtioError::ArithmeticOverflow)?;
        let total_size = used_offset
            .checked_add(used_bytes)
            .ok_or(VirtioError::ArithmeticOverflow)?;
        Ok(Self {
            descriptor_offset: 0,
            available_offset: descriptor_bytes,
            used_offset,
            total_size,
        })
    }
}

fn align_up(value: usize, alignment: usize) -> VirtioResult<usize> {
    value
        .checked_add(alignment - 1)
        .map(|aligned| aligned & !(alignment - 1))
        .ok_or(VirtioError::ArithmeticOverflow)
}

pub struct SplitVirtqueue<M> {
    memory: M,
    size: u16,
    layout: VirtqueueLayout,
    free: Vec<u16>,
    next: Vec<Option<u16>>,
    active_heads: Vec<bool>,
    available_index: u16,
    last_used_index: u16,
}

impl<M: DmaMemory> SplitVirtqueue<M> {
    pub fn new(mut memory: M, size: u16) -> VirtioResult<Self> {
        let layout = VirtqueueLayout::calculate(size)?;
        if memory.len() < layout.total_size {
            return Err(VirtioError::DmaBufferTooSmall);
        }
        memory.bytes_mut()[..layout.total_size].fill(0);
        let free = (0..size).rev().collect();
        Ok(Self {
            memory,
            size,
            layout,
            free,
            next: vec![None; usize::from(size)],
            active_heads: vec![false; usize::from(size)],
            available_index: 0,
            last_used_index: 0,
        })
    }

    pub const fn size(&self) -> u16 {
        self.size
    }

    pub const fn layout(&self) -> VirtqueueLayout {
        self.layout
    }

    pub fn memory(&self) -> &M {
        &self.memory
    }

    pub fn memory_mut(&mut self) -> &mut M {
        &mut self.memory
    }

    pub fn descriptor_address(&self) -> VirtioResult<u64> {
        self.address_at(self.layout.descriptor_offset)
    }

    pub fn available_address(&self) -> VirtioResult<u64> {
        self.address_at(self.layout.available_offset)
    }

    pub fn used_address(&self) -> VirtioResult<u64> {
        self.address_at(self.layout.used_offset)
    }

    pub fn free_descriptor_count(&self) -> usize {
        self.free.len()
    }

    fn address_at(&self, offset: usize) -> VirtioResult<u64> {
        self.memory
            .device_address()
            .checked_add(offset as u64)
            .ok_or(VirtioError::ArithmeticOverflow)
    }

    pub fn enqueue(&mut self, descriptors: &[Descriptor]) -> VirtioResult<u16> {
        if descriptors.is_empty() || descriptors.iter().any(|descriptor| descriptor.length == 0) {
            return Err(VirtioError::InvalidDescriptor);
        }
        if descriptors.len() > self.free.len() {
            return Err(VirtioError::QueueFull);
        }

        let mut allocated = Vec::with_capacity(descriptors.len());
        for _ in descriptors {
            match self.free.pop() {
                Some(index) => allocated.push(index),
                None => {
                    self.free.extend(allocated.into_iter().rev());
                    return Err(VirtioError::QueueFull);
                }
            }
        }
        let head = allocated[0];
        if self.active_heads[usize::from(head)] {
            self.free.extend(allocated.into_iter().rev());
            return Err(VirtioError::InvalidDescriptor);
        }

        for (position, descriptor) in descriptors.iter().enumerate() {
            let index = allocated[position];
            let following = allocated.get(position + 1).copied();
            self.next[usize::from(index)] = following;
            let mut flags = 0;
            if following.is_some() {
                flags |= DESCRIPTOR_F_NEXT;
            }
            if descriptor.device_writable {
                flags |= DESCRIPTOR_F_WRITE;
            }
            self.write_descriptor(index, *descriptor, flags, following.unwrap_or(0))?;
        }
        self.active_heads[usize::from(head)] = true;

        let slot = usize::from(self.available_index % self.size);
        let ring_offset = self
            .layout
            .available_offset
            .checked_add(4)
            .and_then(|offset| offset.checked_add(slot * 2))
            .ok_or(VirtioError::ArithmeticOverflow)?;
        self.write_u16(ring_offset, head)?;
        fence(Ordering::Release);
        self.available_index = self.available_index.wrapping_add(1);
        self.write_u16(self.layout.available_offset + 2, self.available_index)?;
        self.memory.sync_for_device()?;
        Ok(head)
    }

    pub fn pop_used(&mut self) -> VirtioResult<Option<UsedDescriptor>> {
        self.memory.sync_for_cpu()?;
        fence(Ordering::Acquire);
        let device_index = self.read_u16(self.layout.used_offset + 2)?;
        let pending = device_index.wrapping_sub(self.last_used_index);
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.size {
            return Err(VirtioError::InvalidUsedIndex);
        }
        let slot = usize::from(self.last_used_index % self.size);
        let element_offset = self
            .layout
            .used_offset
            .checked_add(4)
            .and_then(|offset| offset.checked_add(slot * USED_ELEMENT_SIZE))
            .ok_or(VirtioError::ArithmeticOverflow)?;
        let raw_head = self.read_u32(element_offset)?;
        let head = u16::try_from(raw_head).map_err(|_| VirtioError::InvalidUsedIndex)?;
        if head >= self.size || !self.active_heads[usize::from(head)] {
            return Err(VirtioError::InvalidUsedIndex);
        }
        let written = self.read_u32(element_offset + 4)?;
        self.release_chain(head)?;
        self.last_used_index = self.last_used_index.wrapping_add(1);
        Ok(Some(UsedDescriptor { head, written }))
    }

    pub fn wait_for_used(
        &mut self,
        head: u16,
        max_polls: u32,
        mut poll: impl FnMut(),
    ) -> VirtioResult<UsedDescriptor> {
        if head >= self.size || !self.active_heads[usize::from(head)] {
            return Err(VirtioError::InvalidDescriptor);
        }
        for _ in 0..max_polls {
            while let Some(completed) = self.pop_used()? {
                if completed.head == head {
                    return Ok(completed);
                }
            }
            poll();
        }
        Err(VirtioError::CommandTimeout)
    }

    fn release_chain(&mut self, head: u16) -> VirtioResult<()> {
        self.active_heads[usize::from(head)] = false;
        let mut current = Some(head);
        let mut released = 0u16;
        while let Some(index) = current {
            if index >= self.size || released >= self.size {
                return Err(VirtioError::InvalidDescriptor);
            }
            current = self.next[usize::from(index)].take();
            self.free.push(index);
            released = released.saturating_add(1);
        }
        Ok(())
    }

    fn write_descriptor(
        &mut self,
        index: u16,
        descriptor: Descriptor,
        flags: u16,
        next: u16,
    ) -> VirtioResult<()> {
        let offset = usize::from(index)
            .checked_mul(DESCRIPTOR_SIZE)
            .ok_or(VirtioError::ArithmeticOverflow)?;
        self.write_u64(offset, descriptor.address)?;
        self.write_u32(offset + 8, descriptor.length)?;
        self.write_u16(offset + 12, flags)?;
        self.write_u16(offset + 14, next)
    }

    fn read_u16(&self, offset: usize) -> VirtioResult<u16> {
        let bytes = self
            .memory
            .bytes()
            .get(offset..offset + 2)
            .ok_or(VirtioError::DmaBufferTooSmall)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&self, offset: usize) -> VirtioResult<u32> {
        let bytes = self
            .memory
            .bytes()
            .get(offset..offset + 4)
            .ok_or(VirtioError::DmaBufferTooSmall)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn write_u16(&mut self, offset: usize, value: u16) -> VirtioResult<()> {
        let bytes = self
            .memory
            .bytes_mut()
            .get_mut(offset..offset + 2)
            .ok_or(VirtioError::DmaBufferTooSmall)?;
        bytes.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u32(&mut self, offset: usize, value: u32) -> VirtioResult<()> {
        let bytes = self
            .memory
            .bytes_mut()
            .get_mut(offset..offset + 4)
            .ok_or(VirtioError::DmaBufferTooSmall)?;
        bytes.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    fn write_u64(&mut self, offset: usize, value: u64) -> VirtioResult<()> {
        let bytes = self
            .memory
            .bytes_mut()
            .get_mut(offset..offset + 8)
            .ok_or(VirtioError::DmaBufferTooSmall)?;
        bytes.copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use plugkit_sys::DmaBuffer;

    use super::*;

    fn queue(size: u16) -> SplitVirtqueue<DmaBuffer> {
        let layout = VirtqueueLayout::calculate(size).unwrap();
        SplitVirtqueue::new(DmaBuffer::new(layout.total_size, 0x4000), size).unwrap()
    }

    fn descriptor(address: u64) -> Descriptor {
        Descriptor {
            address,
            length: 64,
            device_writable: false,
        }
    }

    fn complete(queue: &mut SplitVirtqueue<DmaBuffer>, used_index: u16, head: u32, written: u32) {
        let layout = queue.layout();
        let slot = usize::from(used_index.wrapping_sub(1) % queue.size());
        let offset = layout.used_offset + 4 + slot * USED_ELEMENT_SIZE;
        queue.memory_mut().as_mut_slice()[offset..offset + 4].copy_from_slice(&head.to_le_bytes());
        queue.memory_mut().as_mut_slice()[offset + 4..offset + 8]
            .copy_from_slice(&written.to_le_bytes());
        queue.memory_mut().as_mut_slice()[layout.used_offset + 2..layout.used_offset + 4]
            .copy_from_slice(&used_index.to_le_bytes());
    }

    #[test]
    fn allocates_descriptor_chain_and_available_entry() {
        let mut queue = queue(8);
        let head = queue
            .enqueue(&[
                descriptor(0x8000),
                Descriptor {
                    address: 0x9000,
                    length: 32,
                    device_writable: true,
                },
            ])
            .unwrap();
        assert_eq!(head, 0);
        assert_eq!(queue.free_descriptor_count(), 6);
        let bytes = queue.memory().as_slice();
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 0x8000);
        assert_eq!(u16::from_le_bytes(bytes[12..14].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(bytes[14..16].try_into().unwrap()), 1);
        assert_eq!(
            u16::from_le_bytes(bytes[16 + 12..16 + 14].try_into().unwrap()),
            DESCRIPTOR_F_WRITE
        );
        let available = queue.layout().available_offset;
        assert_eq!(
            u16::from_le_bytes(bytes[available + 2..available + 4].try_into().unwrap()),
            1
        );
        assert_eq!(
            u16::from_le_bytes(bytes[available + 4..available + 6].try_into().unwrap()),
            head
        );
    }

    #[test]
    fn reports_queue_full_without_losing_descriptors() {
        let mut queue = queue(2);
        queue
            .enqueue(&[descriptor(0x8000), descriptor(0x9000)])
            .unwrap();
        assert_eq!(
            queue.enqueue(&[descriptor(0xa000)]),
            Err(VirtioError::QueueFull)
        );
        assert_eq!(queue.free_descriptor_count(), 0);
    }

    #[test]
    fn reclaims_completed_chain() {
        let mut queue = queue(4);
        let head = queue
            .enqueue(&[descriptor(0x8000), descriptor(0x9000)])
            .unwrap();
        complete(&mut queue, 1, u32::from(head), 17);
        assert_eq!(
            queue.pop_used().unwrap(),
            Some(UsedDescriptor { head, written: 17 })
        );
        assert_eq!(queue.free_descriptor_count(), 4);
    }

    #[test]
    fn handles_used_ring_wraparound() {
        let mut queue = queue(2);
        queue.last_used_index = u16::MAX;
        let head = queue.enqueue(&[descriptor(0x8000)]).unwrap();
        complete(&mut queue, 0, u32::from(head), 8);
        assert_eq!(queue.pop_used().unwrap().unwrap().head, head);
        assert_eq!(queue.last_used_index, 0);
    }

    #[test]
    fn rejects_invalid_used_descriptor() {
        let mut queue = queue(4);
        let _ = queue.enqueue(&[descriptor(0x8000)]).unwrap();
        complete(&mut queue, 1, 7, 0);
        assert_eq!(queue.pop_used(), Err(VirtioError::InvalidUsedIndex));
    }

    #[test]
    fn rejects_used_index_jump_larger_than_queue() {
        let mut queue = queue(4);
        let _ = queue.enqueue(&[descriptor(0x8000)]).unwrap();
        let used = queue.layout().used_offset;
        queue.memory_mut().as_mut_slice()[used + 2..used + 4].copy_from_slice(&5u16.to_le_bytes());
        assert_eq!(queue.pop_used(), Err(VirtioError::InvalidUsedIndex));
    }

    #[test]
    fn wait_times_out_without_reusing_chain() {
        let mut queue = queue(4);
        let head = queue.enqueue(&[descriptor(0x8000)]).unwrap();
        assert_eq!(
            queue.wait_for_used(head, 3, || {}),
            Err(VirtioError::CommandTimeout)
        );
        assert_eq!(queue.free_descriptor_count(), 3);
    }

    #[test]
    fn validates_queue_size_and_dma_length() {
        assert_eq!(
            VirtqueueLayout::calculate(3),
            Err(VirtioError::InvalidQueueSize)
        );
        assert!(matches!(
            SplitVirtqueue::new(DmaBuffer::new(8, 0x1000), 8),
            Err(VirtioError::DmaBufferTooSmall)
        ));
    }
}
