//! x86 KPTI mappings needed before SWAPGS/CR3 switch. ARM uses TTBR1 instead.
use super::*;
use core::arch::asm;

fn clone_kernel_l1_table_without_user_entries(src_l1_phys: u64, phys_off: u64) -> Result<u64> {
    let src_l1 = unsafe { &*((src_l1_phys + phys_off) as *const PageTable) };
    let new_l1_frame = allocate_zeroed_page_table()?;
    let new_l1_phys = new_l1_frame.start_address().as_u64();
    let new_l1 = unsafe { &mut *((new_l1_phys + phys_off) as *mut PageTable) };

    for i in 0..512 {
        let entry = src_l1[i].clone();
        let flags = entry.flags();
        if entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }
        if flags.contains(PageTableFlags::USER_ACCESSIBLE) {
            continue;
        }
        new_l1[i] = entry;
    }

    Ok(new_l1_phys)
}

fn clone_kernel_l2_table_without_user_entries(src_l2_phys: u64, phys_off: u64) -> Result<u64> {
    let src_l2 = unsafe { &*((src_l2_phys + phys_off) as *const PageTable) };
    let new_l2_frame = allocate_zeroed_page_table()?;
    let new_l2_phys = new_l2_frame.start_address().as_u64();
    let new_l2 = unsafe { &mut *((new_l2_phys + phys_off) as *mut PageTable) };

    for i in 0..512 {
        let entry = src_l2[i].clone();
        let flags = entry.flags();
        if entry.is_unused() || !flags.contains(PageTableFlags::PRESENT) {
            continue;
        }

        if flags.contains(PageTableFlags::HUGE_PAGE) {
            if !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                new_l2[i] = entry;
            }
            continue;
        }

        let new_l1_phys =
            match clone_kernel_l1_table_without_user_entries(entry.addr().as_u64(), phys_off) {
                Ok(phys) => phys,
                Err(error) => {
                    for cloned_entry in new_l2.iter() {
                        let cloned_flags = cloned_entry.flags();
                        if !cloned_entry.is_unused()
                            && cloned_flags.contains(PageTableFlags::PRESENT)
                            && cloned_flags.contains(PageTableFlags::USER_ACCESSIBLE)
                            && !cloned_flags.contains(PageTableFlags::HUGE_PAGE)
                        {
                            deallocate_4k_frame_by_phys(cloned_entry.addr().as_u64());
                        }
                    }
                    deallocate_4k_frame_by_phys(new_l2_phys);
                    return Err(error);
                }
            };
        new_l2[i].set_addr(
            PhysAddr::new(new_l1_phys),
            flags | PageTableFlags::USER_ACCESSIBLE,
        );
    }

    Ok(new_l2_phys)
}

pub(super) fn initialize_user_root(new_l4_phys: u64, phys_off: u64) -> Result<()> {
    // カーネルの「元の」L4テーブルを使用する（syscall中はCR3がユーザープロセスのテーブルなため）
    let kernel_l4_phys = KERNEL_L4_PHYS.load(core::sync::atomic::Ordering::Relaxed);
    if !KERNEL_L4_READY.load(core::sync::atomic::Ordering::Acquire) {
        crate::kernel::early_serial("paging: kernel L4 not ready\n");
        return Err(Kernel::Memory(Memory::NotMapped));
    }
    let kernel_l4 = unsafe { &*((kernel_l4_phys + phys_off) as *const PageTable) };

    let new_l4 = unsafe { &mut *((new_l4_phys + phys_off) as *mut PageTable) };

    // KPTI強化: L4[0]（低位512GiB）のみ最小限コピーする。
    // これにより上位L4エントリを通じた広域カーネルマッピングをユーザーテーブルから除外する。
    // 実際のユーザー領域は exec/mmap 時に個別マップされる。
    if !kernel_l4[0].is_unused() {
        let kernel_l3_phys = kernel_l4[0].addr().as_u64();
        let kernel_l3 = unsafe { &*((kernel_l3_phys + phys_off) as *const PageTable) };

        let new_l3_frame = allocate_zeroed_page_table()?;
        let new_l3_phys = new_l3_frame.start_address().as_u64();
        let new_l3 = unsafe { &mut *((new_l3_phys + phys_off) as *mut PageTable) };
        new_l4[0].set_addr(
            PhysAddr::new(new_l3_phys),
            kernel_l4[0].flags() | PageTableFlags::USER_ACCESSIBLE,
        );

        // L3[0]: 最初の1GB（カーネルコード・スタックとユーザーコードが混在）
        if !kernel_l3[0].is_unused() {
            let kernel_l3_flags = kernel_l3[0].flags();
            let new_l2_phys = if kernel_l3_flags.contains(PageTableFlags::HUGE_PAGE) {
                let new_l2_frame = allocate_zeroed_page_table()?;
                let new_l2_phys = new_l2_frame.start_address().as_u64();
                let new_l2 = unsafe { &mut *((new_l2_phys + phys_off) as *mut PageTable) };
                let huge_phys = kernel_l3[0].addr().as_u64();
                let mut leaf_flags = kernel_l3_flags;
                leaf_flags.remove(PageTableFlags::USER_ACCESSIBLE);
                for (index, entry) in new_l2.iter_mut().enumerate() {
                    entry.set_addr(
                        PhysAddr::new(huge_phys + (index as u64 * 2 * 1024 * 1024)),
                        leaf_flags,
                    );
                }
                new_l2_phys
            } else {
                clone_kernel_l2_table_without_user_entries(kernel_l3[0].addr().as_u64(), phys_off)?
            };
            let mut new_l3_flags = kernel_l3_flags | PageTableFlags::USER_ACCESSIBLE;
            new_l3_flags.remove(PageTableFlags::HUGE_PAGE);
            new_l3_flags |= PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

            new_l3[0].set_addr(PhysAddr::new(new_l2_phys), new_l3_flags);
        }
    }

    // 0x800000 アドレス（ユーザーコード領域）用に新しい L3/L2/L1 テーブルを事前に割り当てる
    let user_l3_phys = new_l4[0].addr().as_u64();
    if user_l3_phys != 0 {
        let user_l3 = unsafe { &mut *((user_l3_phys + phys_off) as *mut PageTable) };

        if user_l3[0].is_unused() {
            let new_l2_frame = allocate_zeroed_page_table()?;
            user_l3[0].set_addr(
                new_l2_frame.start_address(),
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE,
            );
        } else {
            let l2_addr = user_l3[0].addr();
            let l2_flags = user_l3[0].flags() | PageTableFlags::USER_ACCESSIBLE;
            user_l3[0].set_addr(l2_addr, l2_flags);
        }
        let user_l2_phys = user_l3[0].addr().as_u64();
        let user_l2 = unsafe { &mut *((user_l2_phys + phys_off) as *mut PageTable) };

        // L2[4] エントリ（0x800000-0x9FFFFF）に新しいL1テーブルをセット
        // NOTE: L2 エントリは 2MiB 単位なので、0x800000 >> 21 == 4
        let new_l1_frame = allocate_zeroed_page_table()?;
        let new_l1_phys = new_l1_frame.start_address().as_u64();
        let old_entry = user_l2[4].clone();
        let old_flags = old_entry.flags();
        if !old_entry.is_unused()
            && old_flags.contains(PageTableFlags::PRESENT)
            && old_flags.contains(PageTableFlags::USER_ACCESSIBLE)
            && !old_flags.contains(PageTableFlags::HUGE_PAGE)
        {
            deallocate_4k_frame_by_phys(old_entry.addr().as_u64());
        }
        user_l2[4].set_addr(
            PhysAddr::new(new_l1_phys),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
    }

    if let Err(error) = map_cpu_descriptor_tables_in_user_table(new_l4_phys) {
        crate::kernel::early_serial("paging: descriptor mapping failed\n");
        crate::warn!(
            "Failed to map CPU descriptor tables into user page table: {:?}",
            error
        );
        return Err(error);
    }
    if let Err(error) = unsafe { crate::percpu::map_syscall_shared_region_in_table(new_l4_phys) } {
        crate::kernel::early_serial("paging: syscall region mapping failed\n");
        crate::warn!(
            "Failed to map syscall shared region into user page table: {:?}",
            error
        );
        return Err(error);
    }

    Ok(())
}

fn map_cpu_descriptor_tables_in_user_table(table_phys: u64) -> Result<()> {
    fn map_descriptor_page_supervisor_only(table_phys: u64, page: u64) -> Result<()> {
        use crate::arch::memory::paging::PageTableFlags as Flags;

        let phys_off = physical_memory_offset().ok_or(Kernel::Memory(Memory::NotMapped))?;
        let vaddr = VirtAddr::new(page);
        let l4 = unsafe { &mut *((table_phys + phys_off) as *mut PageTable) };

        let l4e = &mut l4[vaddr.p4_index()];
        if l4e.is_unused() || !l4e.flags().contains(Flags::PRESENT) {
            crate::kernel::early_serial("paging: descriptor L4 missing\n");
            return Err(Kernel::Memory(Memory::NotMapped));
        }
        l4e.set_addr(l4e.addr(), l4e.flags() | Flags::USER_ACCESSIBLE);

        let l3 = unsafe { &mut *((l4e.addr().as_u64() + phys_off) as *mut PageTable) };
        let l3e = &mut l3[vaddr.p3_index()];
        if l3e.is_unused() || !l3e.flags().contains(Flags::PRESENT) {
            crate::kernel::early_serial("paging: descriptor L3 missing\n");
            return Err(Kernel::Memory(Memory::NotMapped));
        }
        if l3e.flags().contains(Flags::HUGE_PAGE) {
            crate::kernel::early_serial("paging: descriptor L3 huge\n");
            return Err(Kernel::Memory(Memory::InvalidAddress));
        }
        l3e.set_addr(l3e.addr(), l3e.flags() | Flags::USER_ACCESSIBLE);

        let l2 = unsafe { &mut *((l3e.addr().as_u64() + phys_off) as *mut PageTable) };
        let l2e = &mut l2[vaddr.p2_index()];
        if l2e.is_unused() {
            let new_l1_frame = allocate_zeroed_page_table()?;
            l2e.set_addr(
                new_l1_frame.start_address(),
                Flags::PRESENT | Flags::WRITABLE | Flags::USER_ACCESSIBLE,
            );
        } else if !l2e.flags().contains(Flags::PRESENT) {
            crate::kernel::early_serial("paging: descriptor L2 not present\n");
            return Err(Kernel::Memory(Memory::NotMapped));
        }

        if l2e.flags().contains(Flags::HUGE_PAGE) {
            let huge_phys = l2e.addr().as_u64();
            let mut base_flags = l2e.flags();
            base_flags.remove(Flags::HUGE_PAGE | Flags::USER_ACCESSIBLE);

            let new_l1_frame = allocate_zeroed_page_table()?;
            let new_l1_phys = new_l1_frame.start_address().as_u64();
            let new_l1 = unsafe { &mut *((new_l1_phys + phys_off) as *mut PageTable) };
            for i in 0..512 {
                new_l1[i].set_addr(PhysAddr::new(huge_phys + (i as u64 * 4096)), base_flags);
            }

            l2e.set_addr(
                PhysAddr::new(new_l1_phys),
                (base_flags | Flags::USER_ACCESSIBLE) & !Flags::NO_EXECUTE,
            );
        } else {
            l2e.set_addr(l2e.addr(), l2e.flags() | Flags::USER_ACCESSIBLE);
        }

        let l1 = unsafe { &mut *((l2e.addr().as_u64() + phys_off) as *mut PageTable) };
        let l1e = &mut l1[vaddr.p1_index()];
        if l1e.is_unused() || !l1e.flags().contains(Flags::PRESENT) {
            let Some(phys) = translate_addr(vaddr).map(|address| address.as_u64() & !0xfff) else {
                crate::kernel::early_serial("paging: descriptor translation missing\n");
                return Err(Kernel::Memory(Memory::NotMapped));
            };
            l1e.set_addr(
                PhysAddr::new(phys),
                Flags::PRESENT | Flags::NO_EXECUTE | KERNEL_MAPPING,
            );
        } else {
            let mut flags = l1e.flags();
            flags.remove(Flags::WRITABLE | Flags::USER_ACCESSIBLE);
            flags |= Flags::NO_EXECUTE | KERNEL_MAPPING;
            l1e.set_addr(l1e.addr(), flags);
        }

        Ok(())
    }

    fn map_current_range(table_phys: u64, base: u64, limit: u16) -> Result<()> {
        let start = base & !0xfff;
        let end = base
            .checked_add(u64::from(limit))
            .ok_or(Kernel::Memory(Memory::OutOfMemory))?
            | 0xfff;
        let mut page = start;
        while page <= end {
            map_descriptor_page_supervisor_only(table_phys, page)?;
            page = page
                .checked_add(4096)
                .ok_or(Kernel::Memory(Memory::OutOfMemory))?;
        }
        Ok(())
    }

    let mut gdtr = [0u8; 10];
    let mut idtr = [0u8; 10];
    unsafe {
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
    }
    let gdt_limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
    let gdt_base = u64::from_le_bytes([
        gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
    ]);
    let idt_limit = u16::from_le_bytes([idtr[0], idtr[1]]);
    let idt_base = u64::from_le_bytes([
        idtr[2], idtr[3], idtr[4], idtr[5], idtr[6], idtr[7], idtr[8], idtr[9],
    ]);

    if let Err(error) = map_current_range(table_phys, gdt_base, gdt_limit) {
        crate::kernel::early_serial("paging: GDT mapping failed\n");
        crate::warn!(
            "Failed to map GDT range {:#x}+{:#x}: {:?}",
            gdt_base,
            gdt_limit,
            error
        );
        return Err(error);
    }
    if let Err(error) = map_current_range(table_phys, idt_base, idt_limit) {
        crate::kernel::early_serial("paging: IDT mapping failed\n");
        crate::warn!(
            "Failed to map IDT range {:#x}+{:#x}: {:?}",
            idt_base,
            idt_limit,
            error
        );
        return Err(error);
    }
    Ok(())
}

fn descriptor_table_ranges() -> [(u64, u64); 2] {
    let mut gdtr = [0u8; 10];
    let mut idtr = [0u8; 10];
    unsafe {
        asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack, preserves_flags));
        asm!("sidt [{}]", in(reg) idtr.as_mut_ptr(), options(nostack, preserves_flags));
    }
    let gdt_limit = u16::from_le_bytes([gdtr[0], gdtr[1]]);
    let gdt_base = u64::from_le_bytes([
        gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
    ]);
    let idt_limit = u16::from_le_bytes([idtr[0], idtr[1]]);
    let idt_base = u64::from_le_bytes([
        idtr[2], idtr[3], idtr[4], idtr[5], idtr[6], idtr[7], idtr[8], idtr[9],
    ]);
    [(gdt_base, gdt_limit), (idt_base, idt_limit)].map(|(base, limit)| {
        (
            base & !4095,
            base.saturating_add(u64::from(limit)).saturating_add(4096) & !4095,
        )
    })
}

pub(super) fn required_kernel_ranges() -> [(u64, u64); 4] {
    let [gdt, idt] = descriptor_table_ranges();
    [
        kernel_image_range(),
        (
            crate::percpu::SYSCALL_SHARED_BASE,
            crate::percpu::SYSCALL_SHARED_STACK_BASE + (crate::percpu::MAX_CPUS as u64) * 4096,
        ),
        gdt,
        idt,
    ]
}

pub(super) fn is_preinstalled_user_mapping(vaddr: u64) -> bool {
    let page = vaddr & !4095;
    required_kernel_ranges()
        .into_iter()
        .any(|(start, end)| start < end && page < end && start < page + 4096)
}
