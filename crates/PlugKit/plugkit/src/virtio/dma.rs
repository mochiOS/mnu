use plugkit_sys::{DmaBuffer, PlugKitResources};

use super::error::{VirtioError, VirtioResult};

pub trait DmaMemory {
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn device_address(&self) -> u64;
    fn bytes(&self) -> &[u8];
    fn bytes_mut(&mut self) -> &mut [u8];
    fn sync_for_device(&self) -> VirtioResult<()>;
    fn sync_for_cpu(&self) -> VirtioResult<()>;
}

pub trait DmaAllocator {
    type Memory: DmaMemory;

    fn allocate_dma(&mut self, size: usize, alignment: usize) -> VirtioResult<Self::Memory>;
}

impl DmaMemory for DmaBuffer {
    fn len(&self) -> usize {
        self.len()
    }

    fn device_address(&self) -> u64 {
        self.device_addr()
    }

    fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn sync_for_device(&self) -> VirtioResult<()> {
        DmaBuffer::sync_for_device(self).map_err(|_| VirtioError::AccessFailed)
    }

    fn sync_for_cpu(&self) -> VirtioResult<()> {
        DmaBuffer::sync_for_cpu(self).map_err(|_| VirtioError::AccessFailed)
    }
}

impl DmaAllocator for PlugKitResources {
    type Memory = DmaBuffer;

    fn allocate_dma(&mut self, size: usize, alignment: usize) -> VirtioResult<Self::Memory> {
        if size == 0 || alignment == 0 || !alignment.is_power_of_two() {
            return Err(VirtioError::InvalidQueueSize);
        }
        self.alloc_dma_aligned(size, alignment)
            .map_err(|_| VirtioError::AccessFailed)
    }
}
