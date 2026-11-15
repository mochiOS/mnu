//! Assigned GICv2 CPU-interface mechanism. No Distributor discovery, routing,
//! device ownership or board addresses belong in this module. EL2 retains
//! those resources and supplies the Domain's virtual CPU interface separately.
use crate::percpu::hardware_id;
use core::{
    arch::asm,
    marker::PhantomData,
    ptr::{read_volatile, write_volatile},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidRange,
    InterruptsEnabled,
    WrongCpu,
    RegisterRejected,
}

/// A CPU-local, privately mapped GICC/GICV register bank. It cannot be sent to
/// another CPU or used as a device-discovery/physical interrupt-routing handle.
pub struct CpuInterface {
    base: u64,
    cpu: u64,
    _local: PhantomData<*mut ()>,
}

impl CpuInterface {
    /// # Safety
    /// Retain this CPU's assigned register bank at `base` for the entire
    /// interface lifetime, mapped privileged RW/Device/XN with IRQs masked.
    /// The range must be a CPU interface, never a Distributor or arbitrary RAM.
    pub unsafe fn new(base: u64, size: u64) -> Result<Self, Error> {
        if base == 0
            || base & 4095 != 0
            || size != mnu_abi::arm64_interrupts::CPU_INTERFACE_SIZE
            || !super::memory::VirtAddr::is_canonical(base)
            || base
                .checked_add(size - 1)
                .is_none_or(|end| !super::memory::VirtAddr::is_canonical(end))
        {
            return Err(Error::InvalidRange);
        }
        if crate::arch::interrupts::are_enabled() {
            return Err(Error::InterruptsEnabled);
        }
        Ok(Self {
            base,
            cpu: hardware_id(),
            _local: PhantomData,
        })
    }

    fn check_cpu(&self) -> Result<(), Error> {
        if hardware_id() != self.cpu {
            return Err(Error::WrongCpu);
        }
        if crate::arch::interrupts::are_enabled() {
            return Err(Error::InterruptsEnabled);
        }
        Ok(())
    }

    fn read(&self, offset: u64) -> u32 {
        // SAFETY: Fixed architectural register offset in the retained bank.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    fn write(&mut self, offset: u64, value: u32) {
        // SAFETY: Fixed architectural register offset in the retained bank.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) };
    }

    /// Enable this CPU's interface with combined priority-drop/deactivation.
    /// In the virtual interface the native Domain receives Group 0 interrupts;
    /// EL2 controls their assignment and physical routing, not this register.
    pub fn enable(&mut self) -> Result<(), Error> {
        self.check_cpu()?;
        self.write(4, 0xff); // PMR
        self.write(8, 0); // BPR (hardware may clamp the implemented priority bits)
        self.write(0, 1); // CTLR, EOImode=0
        unsafe { asm!("dsb sy", "isb", options(nostack, preserves_flags)) };
        if self.read(0) & ((1 << 9) | 1) != 1 {
            return Err(Error::RegisterRejected);
        }
        Ok(())
    }

    pub fn acknowledge(&mut self) -> Result<Option<Pending<'_>>, Error> {
        self.check_cpu()?;
        let acknowledgement = self.read(12);
        if acknowledgement & 1023 >= 1020 {
            // Special/spurious IDs must not receive EOIR writes.
            return Ok(None);
        }
        Ok(Some(Pending {
            interface: self,
            acknowledgement,
        }))
    }
}

/// The complete IAR token is retained, including an SGI's source CPU bits.
/// Complete before scheduling; no other CPU may finish this bank's interrupt.
#[must_use = "complete the acknowledged interrupt before scheduling"]
pub struct Pending<'a> {
    interface: &'a mut CpuInterface,
    acknowledgement: u32,
}

impl Pending<'_> {
    pub fn interrupt(&self) -> u32 {
        self.acknowledgement & 1023
    }

    pub fn complete(self) -> Result<(), Error> {
        self.interface.check_cpu()?;
        // Complete device/timer/shared-memory effects before deactivation.
        unsafe { asm!("dsb sy", options(nostack, preserves_flags)) };
        self.interface.write(16, self.acknowledgement);
        unsafe { asm!("dsb sy", "isb", options(nostack, preserves_flags)) };
        Ok(())
    }
}
