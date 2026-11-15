//! EL2-assigned interrupt resources, independent of board discovery or drivers.
//! Addresses are Domain guest physical addresses. The kernel maps the assigned
//! CPU interface privately; it never receives the physical Distributor here.
use core::mem::size_of;

pub const VERSION: u32 = 1;
pub const INTERFACE_GIC_V2: u32 = 1;
pub const CPU_INTERFACE_SIZE: u64 = 8192;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    pub version: u32,
    pub struct_size: u32,
    pub interface: u32,
    pub reserved: u32,
    pub cpu_interface_base: u64,
    pub cpu_interface_size: u64,
    pub timer_interrupt: u32,
    /// Coalesced edge notifications. Payload remains in the owned EL2 queue;
    /// completing the GIC interrupt does not consume or discard that payload.
    pub event_interrupt: u32,
    /// Edge notification of retained management state, with the same lifetime.
    pub management_interrupt: u32,
    pub tlb_interrupt: u32,
    pub wake_interrupt: u32,
    pub reserved1: [u32; 3],
}

impl Resources {
    pub const fn empty() -> Self {
        Self {
            version: 0,
            struct_size: 0,
            interface: 0,
            reserved: 0,
            cpu_interface_base: 0,
            cpu_interface_size: 0,
            timer_interrupt: 0,
            event_interrupt: 0,
            management_interrupt: 0,
            tlb_interrupt: 0,
            wake_interrupt: 0,
            reserved1: [0; 3],
        }
    }

    pub const fn gic_v2(
        base: u64,
        timer: u32,
        event: u32,
        management: u32,
        tlb: u32,
        wake: u32,
    ) -> Self {
        Self {
            version: VERSION,
            struct_size: size_of::<Self>() as u32,
            interface: INTERFACE_GIC_V2,
            reserved: 0,
            cpu_interface_base: base,
            cpu_interface_size: CPU_INTERFACE_SIZE,
            timer_interrupt: timer,
            event_interrupt: event,
            management_interrupt: management,
            tlb_interrupt: tlb,
            wake_interrupt: wake,
            reserved1: [0; 3],
        }
    }

    pub fn valid(&self) -> bool {
        self.version == VERSION
            && self.struct_size == size_of::<Self>() as u32
            && self.interface == INTERFACE_GIC_V2
            && self.reserved == 0
            && self.reserved1 == [0; 3]
            && self.cpu_interface_size == CPU_INTERFACE_SIZE
            && self.cpu_interface_base & 4095 == 0
            && self
                .cpu_interface_base
                .checked_add(CPU_INTERFACE_SIZE)
                .is_some_and(|end| end <= 1 << 48)
            && (16..32).contains(&self.timer_interrupt)
            && (32..1020).contains(&self.event_interrupt)
            && (32..1020).contains(&self.management_interrupt)
            && self.event_interrupt != self.management_interrupt
            && self.tlb_interrupt < 16
            && self.wake_interrupt < 16
            && self.tlb_interrupt != self.wake_interrupt
    }
}

const _: () = {
    assert!(size_of::<Resources>() == 64);
    assert!(core::mem::align_of::<Resources>() == 8);
    assert!(core::mem::offset_of!(Resources, cpu_interface_base) == 16);
    assert!(core::mem::offset_of!(Resources, timer_interrupt) == 32);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_irq_resource_bounds_and_reservations_are_checked() {
        let valid = Resources::gic_v2(0x2000_0000, 27, 64, 65, 1, 2);
        assert!(valid.valid());
        assert!(Resources {
            cpu_interface_base: 0,
            ..valid
        }
        .valid());
        assert!(!Resources::empty().valid());
        for invalid in [
            Resources {
                version: VERSION + 1,
                ..valid
            },
            Resources {
                struct_size: 63,
                ..valid
            },
            Resources {
                interface: 0,
                ..valid
            },
            Resources {
                reserved: 1,
                ..valid
            },
            Resources {
                reserved1: [0, 0, 1],
                ..valid
            },
            Resources {
                cpu_interface_base: 1,
                ..valid
            },
            Resources {
                cpu_interface_base: u64::MAX - 4095,
                ..valid
            },
            Resources {
                cpu_interface_base: (1 << 48) - 4096,
                ..valid
            },
            Resources {
                cpu_interface_size: 4096,
                ..valid
            },
            Resources {
                timer_interrupt: 15,
                ..valid
            },
            Resources {
                timer_interrupt: 32,
                ..valid
            },
            Resources {
                event_interrupt: 31,
                ..valid
            },
            Resources {
                management_interrupt: 1020,
                ..valid
            },
            Resources {
                event_interrupt: valid.management_interrupt,
                ..valid
            },
            Resources {
                tlb_interrupt: 16,
                ..valid
            },
            Resources {
                wake_interrupt: valid.tlb_interrupt,
                ..valid
            },
        ] {
            assert!(!invalid.valid(), "{:?}", invalid);
        }
    }
}
