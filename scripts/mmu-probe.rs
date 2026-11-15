//! Owns only this fixture's table pool and reference-machine MMIO mappings.
//! The architecture mapper itself contains no board addresses or allocator.
use crate::arch::paging::{Access, Config, Error, Mapper, MemoryType, PageTable, TableMemory};
use crate::{check, emit};
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};

const TABLES: usize = 96;
const ALIAS: u64 = 0x1000_0000;
const KERNEL_ALIAS: u64 = 0xffff_8000_1000_0000;
static mut TABLE_POOL: [PageTable; TABLES] = [const { PageTable::zeroed() }; TABLES];
#[repr(C, align(4096))]
struct DataPage([u64; 512]);
static mut DATA_A: DataPage = DataPage([0; 512]);
static mut DATA_B: DataPage = DataPage([0; 512]);
static mut POOL: Pool = Pool {
    allocated: [false; TABLES],
    remaining: None,
};

struct Pool {
    allocated: [bool; TABLES],
    remaining: Option<usize>,
}

// SAFETY: This reuses the same owned pool, including unpublished-frame return.
unsafe impl crate::arch::memory::paging::FrameAllocator<crate::arch::memory::paging::Size4KiB>
    for Pool
{
    fn allocate_frame(&mut self) -> Option<crate::arch::memory::paging::PhysFrame> {
        let physical = self.allocate_table().ok()?;
        Some(crate::arch::memory::paging::PhysFrame::containing_address(
            crate::arch::memory::PhysAddr::new(physical),
        ))
    }
    unsafe fn deallocate_frame(&mut self, frame: crate::arch::memory::paging::PhysFrame) -> bool {
        unsafe { self.free_table(frame.start_address().as_u64()) };
        true
    }
}

// SAFETY: One fixture CPU exclusively owns the pool. Its physical and kernel
// virtual addresses are identical, mapped as privileged RW/NX before MMU use.
unsafe impl TableMemory for Pool {
    fn allocate_table(&mut self) -> Result<u64, Error> {
        if let Some(remaining) = self.remaining.as_mut() {
            if *remaining == 0 {
                return Err(Error::OutOfMemory);
            }
            *remaining -= 1;
        }
        let index = self
            .allocated
            .iter()
            .position(|used| !*used)
            .ok_or(Error::OutOfMemory)?;
        self.allocated[index] = true;
        let pointer = unsafe { addr_of_mut!(TABLE_POOL).cast::<PageTable>().add(index) };
        unsafe { (*pointer).clear() };
        Ok(pointer as u64)
    }

    unsafe fn free_table(&mut self, physical: u64) {
        let base = addr_of!(TABLE_POOL) as u64;
        check(
            physical >= base && physical < base + TABLES as u64 * 4096,
            "free outside table pool",
        );
        let index = ((physical - base) / 4096) as usize;
        check(
            self.allocated[index] && physical & 4095 == 0,
            "invalid table free",
        );
        self.allocated[index] = false;
    }

    unsafe fn table_ptr(&self, physical: u64) -> *mut PageTable {
        let base = addr_of!(TABLE_POOL) as u64;
        check(
            physical >= base && physical < base + TABLES as u64 * 4096,
            "walk outside table pool",
        );
        check(
            physical & 4095 == 0 && self.allocated[((physical - base) / 4096) as usize],
            "walk of unowned table",
        );
        physical as *mut PageTable
    }
}

extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __user_text_start: u8;
    static __user_text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
    static __data_start: u8;
    static __data_end: u8;
    static __bss_start: u8;
    static __user_stack_start: u8;
    static __user_stack_end: u8;
    static __stack_top: u8;
}

fn access(user: bool, writable: bool, executable: bool) -> Access {
    Access {
        user,
        writable,
        executable,
        memory: MemoryType::Normal,
    }
}

fn region(mapper: &mut Mapper<'_, Pool>, start: u64, end: u64, flags: Access) {
    check(
        start & 4095 == 0 && end & 4095 == 0 && start <= end,
        "unaligned fixture section",
    );
    let mut address = start;
    while address < end {
        check(
            mapper.map(address, address, flags) == Ok(()),
            "fixture mapping failed",
        );
        address += 4096;
    }
}

unsafe fn root(pool: &mut Pool, config: Config) -> u64 {
    let root = pool
        .allocate_table()
        .unwrap_or_else(|_| crate::fail("root allocation"));
    let mut mapper = unsafe { Mapper::new(root, config, pool) }
        .unwrap_or_else(|_| crate::fail("root ownership"));
    region(
        &mut mapper,
        addr_of!(__text_start) as u64,
        addr_of!(__text_end) as u64,
        access(false, false, true),
    );
    region(
        &mut mapper,
        addr_of!(__user_text_start) as u64,
        addr_of!(__user_text_end) as u64,
        access(true, false, true),
    );
    region(
        &mut mapper,
        addr_of!(__rodata_start) as u64,
        addr_of!(__rodata_end) as u64,
        access(false, false, false),
    );
    region(
        &mut mapper,
        addr_of!(__data_start) as u64,
        addr_of!(__data_end) as u64,
        access(false, true, false),
    );
    region(
        &mut mapper,
        addr_of!(__bss_start) as u64,
        addr_of!(__user_stack_start) as u64,
        access(false, true, false),
    );
    region(
        &mut mapper,
        addr_of!(__user_stack_start) as u64,
        addr_of!(__user_stack_end) as u64,
        access(true, true, false),
    );
    region(
        &mut mapper,
        addr_of!(__user_stack_end) as u64,
        addr_of!(__stack_top) as u64,
        access(false, true, false),
    );
    for address in [0x0800_0000, 0x0801_0000, 0x0900_0000] {
        check(
            mapper.map(
                address,
                address,
                Access {
                    memory: MemoryType::Device,
                    ..access(false, true, false)
                },
            ) == Ok(()),
            "MMIO mapping failed",
        );
    }
    root
}

pub fn initialize() {
    let config = Config::detect().unwrap_or_else(|_| crate::fail("unsupported MMU"));
    // SAFETY: Setup runs once with IRQs masked, before the fixture enables MMU.
    unsafe {
        let pool = &mut *addr_of_mut!(POOL);
        let first = root(pool, config);
        let second = root(pool, config);
        let used = pool.allocated.iter().filter(|used| **used).count();
        pool.remaining = Some(1);
        let mut mapper = Mapper::new(first, config, pool).unwrap_or_else(|_| crate::fail("mapper"));
        check(
            mapper.map(
                0x200_0000_0000,
                addr_of!(DATA_A) as u64,
                access(true, true, false),
            ) == Err(Error::OutOfMemory),
            "allocation failure not propagated",
        );
        check(
            mapper.unmap(0x200_0000_0000) == Err(Error::NotMapped),
            "partial table path published",
        );
        pool.remaining = None;
        check(
            pool.allocated.iter().filter(|used| **used).count() == used,
            "table allocation leaked",
        );

        let mut mapper = Mapper::new(first, config, pool).unwrap_or_else(|_| crate::fail("mapper"));
        check(
            mapper.map(ALIAS, addr_of!(DATA_A) as u64, access(true, true, true))
                == Err(Error::InvalidPermissions),
            "W+X accepted",
        );
        check(
            mapper.map(ALIAS, addr_of!(DATA_A) as u64, access(true, true, false)) == Ok(()),
            "first alias mapping",
        );
        check(
            mapper.map(
                KERNEL_ALIAS,
                addr_of!(DATA_A) as u64,
                access(false, true, false),
            ) == Ok(()),
            "first upper-half mapping",
        );
        check(
            mapper.map(ALIAS, addr_of!(DATA_B) as u64, access(true, true, false))
                == Err(Error::AlreadyMapped),
            "mapping overwritten",
        );
        check(
            mapper.map(
                0x0001_0000_0000_0000,
                addr_of!(DATA_A) as u64,
                access(true, true, false),
            ) == Err(Error::InvalidAddress),
            "noncanonical VA accepted",
        );
        let mut mapper =
            Mapper::new(second, config, pool).unwrap_or_else(|_| crate::fail("mapper"));
        check(
            mapper.map(ALIAS, addr_of!(DATA_B) as u64, access(true, true, false)) == Ok(()),
            "second alias mapping",
        );
        check(
            mapper.map(
                KERNEL_ALIAS,
                addr_of!(DATA_B) as u64,
                access(false, true, false),
            ) == Ok(()),
            "second upper-half mapping",
        );
        write_volatile(addr_of_mut!(DATA_A).cast::<u64>(), 0x1111);
        write_volatile(addr_of_mut!(DATA_B).cast::<u64>(), 0x2222);
        check(config.enable(first, first) == Ok(()), "MMU enable");
        emit("Stage-1 MMU enabled\n");
        {
            use crate::arch::memory::{self, paging::PhysFrame, PhysAddr, VirtAddr};
            let first_frame = PhysFrame::containing_address(PhysAddr::new(first));
            let second_frame = PhysFrame::containing_address(PhysAddr::new(second));
            check(
                memory::active_kernel_root() == first_frame,
                "kernel root register",
            );
            memory::activate_user_root(second_frame);
            check(
                memory::active_user_root() == second_frame,
                "user root register",
            );
            check(
                memory::active_kernel_root() == first_frame,
                "user switch changed kernel root",
            );
            check(
                memory::is_root_active(first) && memory::is_root_active(second),
                "dual active roots",
            );
            check(
                read_volatile(ALIAS as *const u64) == 0x2222,
                "shared VM root switch",
            );
            check(
                read_volatile(KERNEL_ALIAS as *const u64) == 0x1111,
                "user switch changed upper mapping",
            );
            memory::flush_page_local(VirtAddr::new(ALIAS));
            memory::activate_kernel_root(second_frame);
            check(
                memory::active_kernel_root() == second_frame,
                "replace kernel root",
            );
            check(
                read_volatile(KERNEL_ALIAS as *const u64) == 0x2222,
                "kernel root retained stale upper mapping",
            );
            memory::activate_kernel_root(first_frame);
            memory::activate_user_root(first_frame);
            check(
                read_volatile(ALIAS as *const u64) == 0x1111,
                "shared VM root restore",
            );
            check(
                read_volatile(KERNEL_ALIAS as *const u64) == 0x1111,
                "kernel upper mapping restore",
            );
            emit("Shared VM root controls PASS\n");
        }
        check(config.switch_lower_root(first, 1) == Ok(()), "first ASID");
        check(
            read_volatile(ALIAS as *const u64) == 0x1111,
            "first translation",
        );
        {
            use crate::arch::memory::paging::PageTableFlags as Flags;
            let mut table = first;
            for shift in [39, 30, 21] {
                let current = &*pool.table_ptr(table);
                table = current[((ALIAS >> shift) & 511) as usize].addr().as_u64();
            }
            let leaf_table = &mut *pool.table_ptr(table);
            let leaf = &mut leaf_table[((ALIAS >> 12) & 511) as usize];
            let frame = leaf.addr();
            let before = leaf.flags();
            check(
                before.contains(
                    Flags::PRESENT | Flags::USER_ACCESSIBLE | Flags::WRITABLE | Flags::NO_EXECUTE,
                ),
                "logical access conversion",
            );
            let software = Flags::from_bits_retain((7 << 9) | (1 << 52));
            leaf.set_addr(frame, before | software);
            check(
                leaf.flags().contains(software),
                "software ownership conversion",
            );
            check(
                read_volatile(ALIAS as *const u64) == 0x1111,
                "software flags changed hardware mapping",
            );
            leaf.set_addr(frame, (before | software) & !Flags::PRESENT);
            check(
                !leaf.is_unused()
                    && !leaf.flags().contains(Flags::PRESENT)
                    && leaf.flags().contains(software),
                "suspended ownership lost",
            );
            check(leaf.addr() == frame, "suspended frame identity lost");
            leaf.set_addr(frame, before);
        }
        check(config.switch_lower_root(second, 2) == Ok(()), "second ASID");
        check(
            read_volatile(ALIAS as *const u64) == 0x2222,
            "ASID isolation",
        );
        check(
            config.switch_lower_root(first, 1) == Ok(()),
            "restore first ASID",
        );
        check(
            read_volatile(ALIAS as *const u64) == 0x1111,
            "retained ASID translation",
        );
        crate::arch::paging::invalidate_asid(1);
        check(config.switch_lower_root(second, 1) == Ok(()), "ASID reuse");
        check(
            read_volatile(ALIAS as *const u64) == 0x2222,
            "ASID reuse retained stale translation",
        );
        crate::arch::paging::invalidate_asid(1);
        check(config.switch_lower_root(first, 1) == Ok(()), "restore root");
        let mut mapper = Mapper::new(first, config, pool).unwrap_or_else(|_| crate::fail("mapper"));
        check(
            mapper.protect(ALIAS, access(true, false, false)) == Ok(()),
            "read-only protection",
        );
        check(
            mapper.protect(ALIAS, access(true, true, false)) == Ok(()),
            "writable protection",
        );
        write_volatile(ALIAS as *mut u64, 0x3333);
        check(
            read_volatile(addr_of!(DATA_A).cast::<u64>()) == 0x3333,
            "live mapping update",
        );
        check(
            mapper.unmap(ALIAS) == Ok(addr_of!(DATA_A) as u64),
            "unmap physical ownership",
        );
        check(
            mapper.unmap(ALIAS) == Err(Error::NotMapped),
            "double unmap accepted",
        );
        {
            use crate::arch::memory::paging::mapper::Translate;
            use crate::arch::memory::paging::{
                Mapper as VmMapper, OffsetPageTable, Page, PageTableFlags as Flags, PhysFrame,
            };
            use crate::arch::memory::{PhysAddr, VirtAddr};
            let root = &mut *pool.table_ptr(first);
            let mut vm = OffsetPageTable::new(root, VirtAddr::zero());
            let page = Page::containing_address(VirtAddr::new(0x1100_0000));
            let frame = PhysFrame::containing_address(PhysAddr::new(addr_of!(DATA_A) as u64));
            let flags =
                Flags::PRESENT | Flags::WRITABLE | Flags::USER_ACCESSIBLE | Flags::NO_EXECUTE;
            vm.map_to(page, frame, flags, pool)
                .unwrap_or_else(|_| crate::fail("VM map adapter"))
                .flush();
            check(vm.translate_page(page) == Ok(frame), "VM frame translation");
            check(
                vm.translate_addr(page.start_address() + 2u64)
                    == Some(frame.start_address() + 2u64),
                "VM byte translation",
            );
            check(
                read_volatile(page.start_address().as_ptr::<u64>()) == 0x3333,
                "VM hardware translation",
            );
            vm.update_flags(page, flags & !Flags::WRITABLE)
                .unwrap_or_else(|_| crate::fail("VM read-only adapter"))
                .flush();
            vm.update_flags(page, flags)
                .unwrap_or_else(|_| crate::fail("VM writable adapter"))
                .flush();
            write_volatile(page.start_address().as_mut_ptr::<u64>(), 0x4444);
            check(
                read_volatile(addr_of!(DATA_A).cast::<u64>()) == 0x4444,
                "VM permission update",
            );
            let (released, flush) = vm
                .unmap(page)
                .unwrap_or_else(|_| crate::fail("VM unmap adapter"));
            flush.flush();
            check(released == frame, "VM frame ownership return");
            emit("Shared VM mapper adapter PASS\n");
        }
        emit("Stage-1 mappings, ASIDs and rollback PASS\n");
    }
}
