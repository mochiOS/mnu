//! 起動時に実行する初期化処理をまとめたモジュール

use crate::{BootInfo, MemoryRegion, Result, debug, interrupt, mem, task, util};

pub mod fs;

pub fn kinit(boot_info: &'static BootInfo) -> Result<&'static [MemoryRegion]> {
    util::console::init();
    util::vga::init(
        boot_info.framebuffer_addr,
        boot_info.framebuffer_size as usize,
        boot_info.screen_width as usize,
        boot_info.screen_height as usize,
        boot_info.stride as usize,
    );

    // CPU機能の初期化（SSE/FPU有効化）
    crate::cpu::init();
    let clock = crate::performance::initialize_clock();
    crate::info!(
        "Performance clock: invariant_tsc={} rdtscp={} frequency_khz={} source={:?}",
        clock.invariant_tsc,
        clock.rdtscp,
        clock.frequency_khz,
        clock.source
    );
    if let Err(error) =
        crate::random::initialize(&boot_info.entropy_seed, boot_info.entropy_seed_valid != 0)
    {
        crate::warn!("CSPRNG unavailable: {:?}", error);
    }
    if !crate::hypervisor_guest::is_active() {
        if let Err(error) = crate::syscall::time::initialize_realtime() {
            crate::warn!("UTC wall clock unavailable: {:?}", error);
        }
    }

    let memory_map = unsafe {
        core::slice::from_raw_parts(
            boot_info.memory_map_addr as *const MemoryRegion,
            boot_info.memory_map_len as usize,
        )
    };

    crate::info!("Memory map has {} regions", memory_map.len());
    for (i, region) in memory_map.iter().enumerate() {
        debug!(
            "  Region {}: {:#x} - {:#x} ({:?})",
            i,
            region.start,
            region.start + region.len,
            region.region_type
        );
        if i < 5 {
            crate::info!(
                "  Region {}: {:#x} - {:#x} ({:?})",
                i,
                region.start,
                region.start + region.len,
                region.region_type
            );
        }
    }

    // 先にフレームアロケータを初期化
    mem::init_frame_allocator(memory_map)?;
    crate::performance::mark_boot(crate::performance::BootMilestone::PageAllocatorReady);

    // メモリ管理の初期化
    mem::init(boot_info)?;
    crate::performance::mark_boot(crate::performance::BootMilestone::EarlyMemoryReady);

    #[cfg(feature = "frame-allocation-failure-injection")]
    crate::percpu::verify_syscall_frame_allocation_rollback()?;

    fs::init();
    crate::performance::mark_boot(crate::performance::BootMilestone::FilesystemMounted);
    crate::config::init();
    crate::capability::path::init_from_kernel_config();
    if crate::hypervisor_guest::is_active() {
        // mDriver may need to wait for Linux driver probing and physical I/O.
        // Keep that work out of the single-threaded boot path: the scheduler
        // and the desktop must be able to start even when hardware is slow or
        // unavailable.
        crate::cext::init_runtime_config();
    } else {
        crate::cext::init_runtime_config();
        crate::cext::register_builtin_cext("disk", crate::cext::CextKind::BlockDevice);
        crate::cext::register_builtin_cext("ext2", crate::cext::CextKind::Filesystem);
        crate::cext::load_modules();
        if crate::cext::fs::is_loaded() {
            if crate::cext::disk::is_loaded() {
                let rc = crate::cext::fs::set_disk_ops(crate::cext::disk::serialized_ops_ptr());
                if rc != 0 {
                    crate::warn!("cext: fs set_disk_ops failed rc={}", rc);
                }
            }
            let rc = crate::cext::fs::mount(0, 0);
            if rc != 0 {
                crate::warn!("cext: fs mount failed rc={}", rc);
            } else {
                crate::audit::flush_to_disk();
            }
        }
    }

    // MED-32修正: PIT初期化をCPU割り込み有効化より前に実行する
    // 以前は enable() が init_pit() より先だったため、PIT未初期化状態でタイマー割り込みが
    // 発生する可能性があった。正しい初期化順序: PIT→スケジューラ→タイマー→割り込み有効化
    task::init_scheduler();
    crate::performance::mark_boot(crate::performance::BootMilestone::SchedulerStarted);
    if crate::hypervisor_guest::is_active() {
        if crate::smp::enable_hypervisor_scheduler_timer() {
            crate::info!("mBoot virtual scheduler timer initialized");
        } else {
            crate::warn!("mBoot virtual scheduler timer unavailable");
        }
    } else {
        interrupt::init_pit();
        interrupt::enable_timer_interrupt();
    }

    x86_64::instructions::interrupts::enable();

    // Initialize syscall MSRs (STAR/LSTAR/FMASK)

    // SYSCALL/SYSRET 命令サポートを初期化
    crate::syscall::syscall_entry::init_syscall();
    crate::performance::mark_boot(crate::performance::BootMilestone::BspReady);

    Ok(memory_map)
}
