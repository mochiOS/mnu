use core::arch::{asm, global_asm};
use core::ptr::addr_of;

use mnu_abi::hypervisor::EVENT_CHANNEL_VECTOR;

const CODE_SELECTOR: u16 = 0x08;
const INTERRUPT_GATE: u8 = 0x8e;

#[unsafe(no_mangle)]
static mut MNU_DOMAIN_EVENT_IRQ_COUNT: u64 = 0;

global_asm!(
    ".global mnu_domain_event_irq",
    "mnu_domain_event_irq:",
    "lock inc qword ptr [rip + MNU_DOMAIN_EVENT_IRQ_COUNT]",
    "iretq",
);

unsafe extern "C" {
    fn mnu_domain_event_irq();
}

#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_middle: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn interrupt(handler: u64) -> Self {
        Self {
            offset_low: handler as u16,
            selector: CODE_SELECTOR,
            ist: 0,
            attributes: INTERRUPT_GATE,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static mut IDT: [IdtEntry; 256] = [IdtEntry::missing(); 256];
static GDT: [u64; 3] = [0, 0x00af_9a00_0000_ffff, 0x00af_9200_0000_ffff];

pub unsafe fn install() {
    let idt = &raw mut IDT;
    unsafe {
        (*idt)[EVENT_CHANNEL_VECTOR as usize] =
            IdtEntry::interrupt(mnu_domain_event_irq as *const () as usize as u64);
    }
    let pointer = DescriptorTablePointer {
        limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
        base: addr_of!(IDT) as u64,
    };
    let gdt_pointer = DescriptorTablePointer {
        limit: (core::mem::size_of::<[u64; 3]>() - 1) as u16,
        base: addr_of!(GDT) as u64,
    };
    unsafe {
        asm!("lgdt [{}]", in(reg) &gdt_pointer, options(readonly, nostack, preserves_flags));
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
        asm!("sti", options(nomem, nostack));
    }
}

#[allow(dead_code)]
pub fn event_count() -> u64 {
    unsafe { (&raw const MNU_DOMAIN_EVENT_IRQ_COUNT).read_volatile() }
}
