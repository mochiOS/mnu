use crate::interrupt::spinlock::SpinLock;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use crate::capability::{CapabilitySet, KernelAuthority, KernelAuthoritySet, KernelCapability};
use crate::result::{Kernel, Process as ProcessError, Result};

use super::handle_table::ObjectHandleTable;
use super::ids::{PrivilegeLevel, ProcessId, ProcessState};
use super::launch_context::LaunchContext;

/// プロセス単位の resource limit
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_threads: usize,
    pub max_ipc_queue: usize,
    pub max_ipc_bytes: usize,
    pub max_mapped_pages: usize,
    pub max_mmio_ranges: usize,
    pub max_irq_binds: usize,
    pub max_cext_instances: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_threads: 64,
            max_ipc_queue: crate::config::kernel().ipc.mailbox_cap,
            max_ipc_bytes: crate::config::kernel().ipc.max_msg_size,
            max_mapped_pages: 4096,
            max_mmio_ranges: 16,
            max_irq_binds: 8,
            max_cext_instances: 8,
        }
    }
}

#[derive(Clone, Debug)]
pub enum MemoryBacking {
    Anonymous {
        data: alloc::vec::Vec<u8>,
        writable: bool,
        shared: bool,
    },
    File {
        object: Arc<crate::mem::vm_object::VmObject>,
        offset: u64,
        writable: bool,
        shared: bool,
    },
}

#[derive(Clone, Debug)]
pub struct MemoryRegion {
    start: u64,
    len: u64,
    access: u64,
    max_access: u64,
    access_ranges: alloc::vec::Vec<MemoryAccessRange>,
    options: u64,
    backing: MemoryBacking,
    dirty_pages: alloc::vec::Vec<u64>,
}

#[derive(Clone, Copy, Debug)]
struct MemoryAccessRange {
    start: u64,
    end: u64,
    access: u64,
}

#[derive(Clone, Debug)]
pub struct DmaBuffer {
    handle: u64,
    virt_start: u64,
    len: u64,
    phys_start: u64,
    page_count: usize,
}

#[derive(Clone, Debug)]
pub struct MmioMapping {
    virt_start: u64,
    len: u64,
    phys_start: u64,
    writable: bool,
}

impl DmaBuffer {
    pub fn new(handle: u64, virt_start: u64, len: u64, phys_start: u64, page_count: usize) -> Self {
        Self {
            handle,
            virt_start,
            len,
            phys_start,
            page_count,
        }
    }

    pub fn handle(&self) -> u64 {
        self.handle
    }

    pub fn virt_start(&self) -> u64 {
        self.virt_start
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn phys_start(&self) -> u64 {
        self.phys_start
    }

    pub fn page_count(&self) -> usize {
        self.page_count
    }

    pub fn end(&self) -> Option<u64> {
        self.virt_start.checked_add(self.len)
    }
}

impl MmioMapping {
    pub fn new(virt_start: u64, len: u64, phys_start: u64, writable: bool) -> Self {
        Self {
            virt_start,
            len,
            phys_start,
            writable,
        }
    }

    pub fn virt_start(&self) -> u64 {
        self.virt_start
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn phys_start(&self) -> u64 {
        self.phys_start
    }

    pub fn writable(&self) -> bool {
        self.writable
    }

    pub fn end(&self) -> Option<u64> {
        self.virt_start.checked_add(self.len)
    }
}

impl MemoryRegion {
    pub fn file_backed(
        start: u64,
        len: u64,
        access: u64,
        options: u64,
        object: Arc<crate::mem::vm_object::VmObject>,
        offset: u64,
        writable: bool,
        shared: bool,
        max_access: u64,
    ) -> Self {
        Self {
            start,
            len,
            access,
            max_access,
            access_ranges: alloc::vec::Vec::new(),
            options,
            backing: MemoryBacking::File {
                object,
                offset,
                writable,
                shared,
            },
            dirty_pages: alloc::vec::Vec::new(),
        }
    }

    pub fn anonymous(
        start: u64,
        len: u64,
        access: u64,
        options: u64,
        writable: bool,
        shared: bool,
    ) -> Self {
        Self {
            start,
            len,
            access,
            max_access: mnu_abi::MEMORY_ACCESS_ALL,
            access_ranges: alloc::vec::Vec::new(),
            options,
            backing: MemoryBacking::Anonymous {
                data: alloc::vec::Vec::new(),
                writable,
                shared,
            },
            dirty_pages: alloc::vec::Vec::new(),
        }
    }

    pub fn start(&self) -> u64 {
        self.start
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn end(&self) -> Option<u64> {
        self.start.checked_add(self.len)
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.end()
            .map(|end| addr >= self.start && addr < end)
            .unwrap_or(false)
    }

    pub fn backing(&self) -> &MemoryBacking {
        &self.backing
    }

    pub fn backing_mut(&mut self) -> &mut MemoryBacking {
        &mut self.backing
    }

    /// Retains an aligned subrange without losing its backing authority,
    /// object offset, dirty-page indices, or access overrides.
    fn slice(&self, start: u64, end: u64) -> Option<Self> {
        if start < self.start || end > self.end()? || start >= end {
            return None;
        }
        let delta = start.checked_sub(self.start)?;
        let mut slice = self.clone();
        slice.start = start;
        slice.len = end - start;
        match &mut slice.backing {
            MemoryBacking::File { offset, .. } => {
                *offset = offset.checked_add(delta)?;
            }
            MemoryBacking::Anonymous { data, .. } if !data.is_empty() => {
                let first = usize::try_from(delta).ok()?;
                let last = usize::try_from(delta.checked_add(slice.len)?).ok()?;
                *data = data.get(first..last)?.to_vec();
            }
            _ => {}
        }
        slice.access_ranges.retain_mut(|range| {
            range.start = range.start.max(start);
            range.end = range.end.min(end);
            range.start < range.end
        });
        let first_page = delta / 4096;
        let last_page = first_page.checked_add(slice.len / 4096)?;
        slice.dirty_pages.retain_mut(|page| {
            if *page < first_page || *page >= last_page {
                return false;
            }
            *page -= first_page;
            true
        });
        Some(slice)
    }

    pub fn set_shared(&mut self, shared: bool) -> bool {
        // A private file mapping may be writable through COW even when its
        // source handle has no WRITE right. Sharing that mapping would turn
        // private writes into unauthorized backing writes. File sharing must
        // be selected by MemoryMap, which validates the source handle rights.
        if shared && !self.is_shared() && self.backing.file_object().is_some() {
            return false;
        }
        if shared {
            self.options |= mnu_abi::MEMORY_MAP_SHARED;
        } else {
            self.options &= !mnu_abi::MEMORY_MAP_SHARED;
        }
        match &mut self.backing {
            MemoryBacking::Anonymous { shared: s, .. } => *s = shared,
            MemoryBacking::File { shared: s, .. } => *s = shared,
        }
        true
    }

    pub fn set_writable(&mut self, writable: bool) {
        match &mut self.backing {
            MemoryBacking::Anonymous { writable: w, .. } => *w = writable,
            MemoryBacking::File { writable: w, .. } => *w = writable,
        }
    }

    pub fn mark_dirty_page(&mut self, page_index: u64) {
        if !self.dirty_pages.contains(&page_index) {
            self.dirty_pages.push(page_index);
        }
    }

    pub fn take_dirty_pages(&mut self) -> alloc::vec::Vec<u64> {
        core::mem::take(&mut self.dirty_pages)
    }

    pub fn clear_dirty_pages(&mut self, first_page: u64, page_count: u64) {
        let end_page = first_page.saturating_add(page_count);
        self.dirty_pages
            .retain(|page| *page < first_page || *page >= end_page);
    }

    pub fn dirty_pages(&self) -> &[u64] {
        &self.dirty_pages
    }

    pub fn is_writable(&self) -> bool {
        self.access & mnu_abi::MEMORY_ACCESS_WRITE != 0
    }

    pub fn allows_read_at(&self, address: u64) -> bool {
        self.access_at(address).is_some_and(|access| access != 0)
    }

    pub fn allows_write_at(&self, address: u64) -> bool {
        self.access_at(address)
            .is_some_and(|access| access & mnu_abi::MEMORY_ACCESS_WRITE != 0)
    }

    pub fn allows_execute_at(&self, address: u64) -> bool {
        self.access_at(address)
            .is_some_and(|access| access & mnu_abi::MEMORY_ACCESS_EXECUTE != 0)
    }

    #[inline(never)]
    pub fn allows_write_range(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        let mut address = start;
        while address < end {
            if !self.allows_write_at(address) {
                return false;
            }
            address = (address | 0xfff).saturating_add(1).min(end);
        }
        true
    }

    #[inline(never)]
    pub fn set_access(&mut self, start: u64, len: u64, access: u64) -> bool {
        if !self.permits_access(access) {
            return false;
        }
        let Some(end) = start.checked_add(len) else {
            return false;
        };
        if start < self.start || end > self.end().unwrap_or(0) || start >= end {
            return false;
        }

        let previous = core::mem::take(&mut self.access_ranges);
        let mut ranges = alloc::vec::Vec::with_capacity(previous.len() + 1);
        for range in previous {
            if range.end <= start || range.start >= end {
                ranges.push(range);
                continue;
            }
            if range.start < start {
                ranges.push(MemoryAccessRange {
                    end: start,
                    ..range
                });
            }
            if range.end > end {
                ranges.push(MemoryAccessRange {
                    start: end,
                    ..range
                });
            }
        }
        if access != self.access {
            ranges.push(MemoryAccessRange { start, end, access });
        }
        ranges.sort_unstable_by_key(|range| range.start);

        for range in ranges {
            if let Some(last) = self.access_ranges.last_mut() {
                if last.end == range.start && last.access == range.access {
                    last.end = range.end;
                    continue;
                }
            }
            self.access_ranges.push(range);
        }
        true
    }

    fn access_at(&self, address: u64) -> Option<u64> {
        if !self.contains(address) {
            return None;
        }
        Some(
            self.access_ranges
                .iter()
                .find(|range| address >= range.start && address < range.end)
                .map_or(self.access, |range| range.access),
        )
    }

    pub fn permits_access(&self, access: u64) -> bool {
        access & !self.max_access == 0
    }

    pub fn is_shared(&self) -> bool {
        self.options & mnu_abi::MEMORY_MAP_SHARED != 0
    }
}

impl MemoryBacking {
    pub fn file_object(&self) -> Option<&Arc<crate::mem::vm_object::VmObject>> {
        match self {
            MemoryBacking::Anonymous { .. } => None,
            MemoryBacking::File { object, .. } => Some(object),
        }
    }

    pub fn file_offset(&self) -> u64 {
        match self {
            MemoryBacking::Anonymous { .. } => 0,
            MemoryBacking::File { offset, .. } => *offset,
        }
    }

    pub fn file_writable(&self) -> bool {
        match self {
            MemoryBacking::Anonymous { writable, .. } => *writable,
            MemoryBacking::File { writable, .. } => *writable,
        }
    }

    pub fn file_shared(&self) -> bool {
        match self {
            MemoryBacking::Anonymous { shared, .. } => *shared,
            MemoryBacking::File { shared, .. } => *shared,
        }
    }
}

/// Stable native process lifecycle object retained by `ProcessHandle`s after
/// execution resources leave the process table.
#[derive(Debug)]
pub struct ProcessObject {
    id: ProcessId,
    state: AtomicU8,
    exit_code: AtomicU64,
}

impl ProcessObject {
    fn new(id: ProcessId) -> Self {
        Self {
            id,
            state: AtomicU8::new(mnu_abi::PROCESS_STATE_RUNNING as u8),
            exit_code: AtomicU64::new(0),
        }
    }

    pub const fn id(&self) -> ProcessId {
        self.id
    }

    pub fn is_exited(&self) -> bool {
        self.state.load(Ordering::Acquire) == mnu_abi::PROCESS_STATE_EXITED as u8
    }

    pub fn exit_code(&self) -> u64 {
        self.exit_code.load(Ordering::Acquire)
    }

    fn mark_exited(&self, exit_code: u64) {
        self.exit_code.store(exit_code, Ordering::Relaxed);
        self.state
            .store(mnu_abi::PROCESS_STATE_EXITED as u8, Ordering::Release);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationProvenance {
    BuiltIn,
    VerifiedPackage,
    Development,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationIdentity {
    package_id: String,
    developer_id: String,
    subject_key_id: [u8; 32],
    provenance: ApplicationProvenance,
}

#[derive(Clone, Debug)]
pub struct PendingExecSecurity {
    pub path: String,
    pub authorized_thread: crate::task::ThreadId,
    pub executable_digest: [u8; 32],
    pub capabilities: CapabilitySet,
    pub kernel_authorities: KernelAuthoritySet,
    pub identity: ApplicationIdentity,
    pub kind: PendingExecKind,
    pub execution_class: mnu_abi::exec::ExecutionClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingExecKind {
    ImageReplace,
    Spawn,
}

impl ApplicationIdentity {
    pub fn new(
        package_id: String,
        developer_id: String,
        subject_key_id: [u8; 32],
        provenance: ApplicationProvenance,
    ) -> Self {
        Self {
            package_id,
            developer_id,
            subject_key_id,
            provenance,
        }
    }

    pub fn package_id(&self) -> &str {
        &self.package_id
    }

    pub fn developer_id(&self) -> &str {
        &self.developer_id
    }

    pub const fn subject_key_id(&self) -> &[u8; 32] {
        &self.subject_key_id
    }

    pub const fn provenance(&self) -> ApplicationProvenance {
        self.provenance
    }
}

/// プロセス構造体
///
/// メモリ空間とリソースを管理する実行単位。
/// 1つ以上のスレッドを持つ。
pub struct Process {
    /// プロセスID
    id: ProcessId,
    object: Arc<ProcessObject>,
    /// 検証済みinstall metadataから導出されたapplication identity。
    application_identity: Option<ApplicationIdentity>,
    /// Measurement of the original loaded bytes, not of mutable runtime pages.
    image_digest: Option<[u8; 32]>,
    pending_exec_security: Option<PendingExecSecurity>,
    /// プロセス名 (固定長バッファ)
    name: [u8; 32],
    /// 有効な名前の長さ
    name_len: usize,
    /// プロセスの状態
    state: ProcessState,
    /// 権限レベル
    privilege: PrivilegeLevel,
    /// プロセスに付与された capability（カーネルが保持）
    ///
    /// ユーザープロセスが自分で capability を増やせると sandbox を回避できるため、
    /// 変更は信頼済みの起動経路からのみ行う。
    capabilities: CapabilitySet,
    /// object-scoped kernel authority
    kernel_authorities: KernelAuthoritySet,
    /// ページテーブルのアドレス（メモリ空間）。Noneの場合はカーネル空間を共有。
    page_table: Option<u64>,
    /// page_table をこの Process が所有しているかどうか
    page_table_owned: bool,
    /// ヒープ開始アドレス
    heap_start: u64,
    /// 現在のヒープ終了アドレス (program break)
    heap_end: u64,
    /// DMA 専用仮想アドレス領域の開始
    dma_start: u64,
    /// DMA 専用仮想アドレス領域の現在位置
    dma_end: u64,
    /// IPCで受信した共有ページ用仮想アドレス領域の現在位置
    ipc_mapping_end: u64,
    /// ユーザースタックの現在の最低マップアドレス（下向きに伸びる）
    stack_bottom: u64,
    /// ユーザースタックのトップアドレス（初期 RSP 付近）
    stack_top: u64,
    /// 実行ファイルのパス
    exe_path: String,
    /// 優先度（0が最高、値が大きいほど低い）
    priority: u8,
    /// 前景プロセスとして待ち時間を優先する
    foreground: bool,
    /// 終了コード（生存中はNone）
    exit_code: Option<u64>,
    /// Process-local references to kernel mechanism objects.
    object_handles: alloc::boxed::Box<ObjectHandleTable>,
    /// Opaque inherited-handle names supplied by the trusted launch path.
    launch_context: alloc::boxed::Box<LaunchContext>,
    /// Native anonymous and object-backed virtual-memory regions.
    memory_regions: alloc::vec::Vec<MemoryRegion>,
    /// 借用 MMIO マッピング
    mmio_mappings: Vec<MmioMapping>,
    /// カーネル管理 DMA バッファ
    dma_buffers: Vec<DmaBuffer>,
    /// プロセスごとの resource limit
    resource_limits: ResourceLimits,
}

impl Process {
    /// 新しいプロセスを作成
    ///
    /// # Arguments
    /// * `name` - プロセス名
    /// * `privilege` - 権限レベル
    /// * `priority` - プロセスの優先度
    pub fn new(
        name: &str,
        privilege: PrivilegeLevel,
        priority: u8,
    ) -> Self {
        let mut name_buf = [0u8; 32];
        let bytes = name.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        // デフォルトのヒープ領域（仮）。exec時に再設定されるべき。
        // 0x40000000番地あたりを開始にする例が多いが、ここでは0にしておく。
        let heap_start = 0;

        let id = ProcessId::new();
        Self {
            id,
            object: Arc::new(ProcessObject::new(id)),
            application_identity: None,
            image_digest: None,
            pending_exec_security: None,
            name: name_buf,
            name_len: len,
            state: ProcessState::Running,
            privilege,
            capabilities: CapabilitySet::empty(),
            kernel_authorities: KernelAuthoritySet::empty(),
            page_table: None, // TODO: ページテーブル実装後に設定
            page_table_owned: true,
            heap_start,
            heap_end: heap_start,
            dma_start: 0,
            dma_end: 0,
            ipc_mapping_end: 0,
            stack_bottom: 0,
            stack_top: 0,
            exe_path: String::new(),
            priority,
            foreground: false,
            exit_code: None,
            object_handles: ObjectHandleTable::new_boxed(),
            launch_context: LaunchContext::new_boxed(),
            memory_regions: alloc::vec::Vec::new(),
            mmio_mappings: Vec::new(),
            dma_buffers: Vec::new(),
            resource_limits: ResourceLimits::default(),
        }
    }

    /// プロセスIDを取得
    pub fn id(&self) -> ProcessId {
        self.id
    }

    pub fn process_object(&self) -> Arc<ProcessObject> {
        Arc::clone(&self.object)
    }

    /// セキュリティIDを取得
    pub fn security_identity(&self) -> Option<&str> {
        self.application_identity
            .as_ref()
            .map(ApplicationIdentity::package_id)
    }

    pub fn application_identity(&self) -> Option<&ApplicationIdentity> {
        self.application_identity.as_ref()
    }

    /// application identityを設定する（信頼済み起動経路専用）。
    pub(crate) fn set_application_identity(&mut self, identity: ApplicationIdentity) {
        self.application_identity = Some(identity);
    }

    pub(crate) fn image_digest(&self) -> Option<[u8; 32]> {
        self.image_digest
    }

    pub(crate) fn set_image_digest(&mut self, digest: [u8; 32]) {
        self.image_digest = Some(digest);
    }

    pub(crate) fn authorize_next_exec(&mut self, authorization: PendingExecSecurity) {
        self.pending_exec_security = Some(authorization);
    }

    pub(crate) fn take_exec_authorization(
        &mut self,
        path: &str,
        thread: crate::task::ThreadId,
    ) -> Option<PendingExecSecurity> {
        if self
            .pending_exec_security
            .as_ref()
            .is_some_and(|authorization| {
                authorization.path == path && authorization.authorized_thread == thread
            })
        {
            self.pending_exec_security.take()
        } else {
            None
        }
    }

    /// サービスIDを取得
    /// capability 集合を取得（読み取り専用）
    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    pub fn kernel_authorities(&self) -> &KernelAuthoritySet {
        &self.kernel_authorities
    }

    /// capability 集合を可変取得（kernel 内部用）
    pub(crate) fn capabilities_mut(&mut self) -> &mut CapabilitySet {
        &mut self.capabilities
    }

    pub(crate) fn kernel_authorities_mut(&mut self) -> &mut KernelAuthoritySet {
        &mut self.kernel_authorities
    }

    /// exec 経路でプロセス生成時に capability を設定する（カーネル内部用）
    ///
    /// # 注意
    /// capability は sandbox の根幹なので、ユーザー空間へ公開しないこと。
    pub(crate) fn set_capabilities_for_exec(&mut self, caps: CapabilitySet) {
        self.capabilities = caps;
    }

    pub(crate) fn set_kernel_authorities_for_exec(&mut self, authorities: KernelAuthoritySet) {
        self.kernel_authorities = authorities;
    }

    /// プロセス名を取得
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("???")
    }

    /// プロセスの状態を取得
    pub fn state(&self) -> ProcessState {
        self.state
    }

    /// プロセスの状態を設定
    pub fn set_state(&mut self, state: ProcessState) {
        self.state = state;
    }

    /// 権限レベルを取得
    pub fn privilege(&self) -> PrivilegeLevel {
        self.privilege
    }

    /// 優先度を取得
    pub fn priority(&self) -> u8 {
        self.priority
    }

    pub fn is_foreground(&self) -> bool {
        self.foreground
    }

    pub fn set_foreground(&mut self, foreground: bool) {
        self.foreground = foreground;
    }

    /// 終了コードを取得
    pub fn exit_code(&self) -> Option<u64> {
        self.exit_code
    }

    /// 終了状態へ遷移
    pub fn mark_exited(&mut self, exit_code: u64) {
        self.state = ProcessState::Zombie;
        self.exit_code = Some(exit_code);
        self.object.mark_exited(exit_code);
    }

    /// ページテーブルアドレスを取得
    pub fn page_table(&self) -> Option<u64> {
        self.page_table
    }

    /// ページテーブルアドレスを設定
    pub fn set_page_table(&mut self, page_table: u64) {
        self.page_table = Some(page_table);
        self.page_table_owned = true;
    }

    /// 既存のページテーブルを共有する
    pub fn set_shared_page_table(&mut self, page_table: u64) {
        self.page_table = Some(page_table);
        self.page_table_owned = false;
    }

    pub fn page_table_owned(&self) -> bool {
        self.page_table_owned
    }

    /// ヒープ終了アドレスを取得
    pub fn heap_end(&self) -> u64 {
        self.heap_end
    }

    /// ヒープ終了アドレスを設定
    pub fn set_heap_end(&mut self, addr: u64) {
        self.heap_end = addr;
    }

    /// ヒープ開始アドレスを取得
    pub fn heap_start(&self) -> u64 {
        self.heap_start
    }

    /// ヒープ開始アドレスを設定
    pub fn set_heap_start(&mut self, addr: u64) {
        self.heap_start = addr;
    }

    pub fn dma_end(&self) -> u64 {
        self.dma_end
    }

    pub fn set_dma_start(&mut self, addr: u64) {
        self.dma_start = addr;
    }

    pub fn set_dma_end(&mut self, addr: u64) {
        self.dma_end = addr;
    }

    pub fn reset_dma_arena(&mut self) {
        self.dma_start = 0;
        self.dma_end = 0;
    }

    pub fn ipc_mapping_end(&self) -> u64 {
        self.ipc_mapping_end
    }

    pub fn set_ipc_mapping_end(&mut self, addr: u64) {
        self.ipc_mapping_end = addr;
    }

    pub fn stack_bottom(&self) -> u64 {
        self.stack_bottom
    }
    pub fn stack_top(&self) -> u64 {
        self.stack_top
    }

    /// System Monitor向けの、カーネルが追跡しているユーザー空間の総量。
    /// 共有領域も各プロセスに一度ずつ数えるため、物理RSSではなくmapped sizeである。
    pub fn mapped_memory_bytes(&self) -> u64 {
        let heap = self.heap_end.saturating_sub(self.heap_start);
        let stack = self.stack_top.saturating_sub(self.stack_bottom);
        let mapped_memory = self
            .memory_regions
            .iter()
            .fold(0u64, |total, region| total.saturating_add(region.len()));
        let dma = self
            .dma_buffers
            .iter()
            .fold(0u64, |total, buffer| total.saturating_add(buffer.len()));
        heap.saturating_add(stack)
            .saturating_add(mapped_memory)
            .saturating_add(dma)
    }
    pub fn set_stack_bottom(&mut self, addr: u64) {
        self.stack_bottom = addr;
    }
    pub fn set_stack_top(&mut self, addr: u64) {
        self.stack_top = addr;
    }

    pub fn exe_path(&self) -> &str {
        &self.exe_path
    }

    pub fn set_exe_path(&mut self, path: &str) {
        self.exe_path.clear();
        self.exe_path.push_str(path);
    }

    pub fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }

    pub fn set_resource_limits(&mut self, limits: ResourceLimits) {
        self.resource_limits = limits;
    }

    pub fn memory_regions(&self) -> &[MemoryRegion] {
        &self.memory_regions
    }

    pub fn memory_regions_mut(&mut self) -> &mut alloc::vec::Vec<MemoryRegion> {
        &mut self.memory_regions
    }

    pub fn set_memory_regions(&mut self, regions: alloc::vec::Vec<MemoryRegion>) {
        self.memory_regions = regions;
    }

    pub fn add_memory_region(&mut self, region: MemoryRegion) -> bool {
        let overlaps = self
            .memory_regions
            .iter()
            .any(|existing| regions_overlap(existing, &region));
        if overlaps {
            return false;
        }
        let mmio_overlap = self.mmio_mappings.iter().any(|existing| {
            let Some(existing_end) = existing.end() else {
                return true;
            };
            let Some(region_end) = region.end() else {
                return true;
            };
            region.start() < existing_end && existing.virt_start() < region_end
        });
        if mmio_overlap {
            return false;
        }
        self.memory_regions.push(region);
        true
    }

    pub fn find_memory_region(&self, addr: u64) -> Option<&MemoryRegion> {
        self.memory_regions
            .iter()
            .find(|region| region.contains(addr))
    }

    pub fn find_memory_region_mut(&mut self, addr: u64) -> Option<&mut MemoryRegion> {
        self.memory_regions
            .iter_mut()
            .find(|region| region.contains(addr))
    }

    pub fn remove_memory_region(&mut self, start: u64, len: u64) -> Option<MemoryRegion> {
        let end = start.checked_add(len)?;
        let idx = self
            .memory_regions
            .iter()
            .position(|region| region.start == start && region.end() == Some(end))?;
        Some(self.memory_regions.remove(idx))
    }

    /// Removes every intersection and keeps the surviving pieces. Build the
    /// replacement before changing state so an invalid slice changes nothing.
    pub fn remove_memory_range(&mut self, start: u64, len: u64) -> Option<Vec<MemoryRegion>> {
        let end = start.checked_add(len)?;
        let mut retained = Vec::new();
        let mut removed = Vec::new();
        for region in &self.memory_regions {
            use super::memory_range::{Range, cut};
            let pieces = cut(
                Range {
                    start: region.start,
                    end: region.end()?,
                },
                Range { start, end },
            )?;
            if let Some(range) = pieces.removed {
                removed.push(region.slice(range.start, range.end)?);
            }
            for range in [pieces.before, pieces.after].into_iter().flatten() {
                retained.push(region.slice(range.start, range.end)?);
            }
        }
        self.memory_regions = retained;
        Some(removed)
    }

    pub fn has_kernel_authority(&self, authority: &KernelAuthority) -> bool {
        self.kernel_authorities.implies(authority)
    }

    pub fn has_kernel_capability_authority(&self, capability: KernelCapability) -> bool {
        self.kernel_authorities.contains_capability(capability)
    }

    pub fn mmio_mappings(&self) -> &[MmioMapping] {
        &self.mmio_mappings
    }

    pub fn mmio_mapping_count(&self) -> usize {
        self.mmio_mappings.len()
    }

    pub fn has_mmio_mappings(&self) -> bool {
        !self.mmio_mappings.is_empty()
    }

    pub fn add_mmio_mapping(&mut self, mapping: MmioMapping) -> bool {
        let Some(mapping_end) = mapping.end() else {
            return false;
        };
        let mmio_overlap = self.mmio_mappings.iter().any(|existing| {
            let Some(existing_end) = existing.end() else {
                return true;
            };
            mapping.virt_start() < existing_end && existing.virt_start() < mapping_end
        });
        if mmio_overlap {
            return false;
        }
        let memory_overlap = self.memory_regions.iter().any(|region| {
            let Some(region_end) = region.end() else {
                return true;
            };
            mapping.virt_start() < region_end && region.start() < mapping_end
        });
        if memory_overlap {
            return false;
        }
        let dma_overlap = self.dma_buffers.iter().any(|existing| {
            let Some(existing_end) = existing.end() else {
                return true;
            };
            mapping.virt_start() < existing_end && existing.virt_start() < mapping_end
        });
        if dma_overlap {
            return false;
        }
        if self.heap_start != 0
            && self.heap_end != 0
            && mapping.virt_start() < self.heap_end
            && self.heap_start < mapping_end
        {
            return false;
        }
        if self.stack_bottom != 0
            && self.stack_top != 0
            && mapping.virt_start() < self.stack_top
            && self.stack_bottom < mapping_end
        {
            return false;
        }
        self.mmio_mappings.push(mapping);
        true
    }

    pub fn remove_mmio_mapping(&mut self, start: u64, len: u64) -> Option<MmioMapping> {
        let end = start.checked_add(len)?;
        let idx = self
            .mmio_mappings
            .iter()
            .position(|mapping| mapping.virt_start() == start && mapping.end() == Some(end))?;
        Some(self.mmio_mappings.remove(idx))
    }

    pub fn find_mmio_mapping_by_addr(&self, addr: u64, len: u64) -> Option<&MmioMapping> {
        let end = addr.checked_add(len)?;
        self.mmio_mappings.iter().find(|mapping| {
            let Some(mapping_end) = mapping.end() else {
                return false;
            };
            addr < mapping_end && mapping.virt_start() < end
        })
    }

    pub fn take_mmio_mappings(&mut self) -> Vec<MmioMapping> {
        core::mem::take(&mut self.mmio_mappings)
    }

    pub fn dma_buffers(&self) -> &[DmaBuffer] {
        &self.dma_buffers
    }

    pub fn add_dma_buffer(&mut self, buffer: DmaBuffer) -> bool {
        let Some(buffer_end) = buffer.end() else {
            return false;
        };
        let dma_overlap = self.dma_buffers.iter().any(|existing| {
            let Some(existing_end) = existing.end() else {
                return true;
            };
            buffer.virt_start < existing_end && existing.virt_start < buffer_end
        });
        if dma_overlap {
            return false;
        }
        let memory_overlap = self.memory_regions.iter().any(|region| {
            let Some(region_end) = region.end() else {
                return true;
            };
            buffer.virt_start < region_end && region.start() < buffer_end
        });
        if memory_overlap {
            return false;
        }
        if self.heap_start != 0
            && self.heap_end != 0
            && buffer.virt_start < self.heap_end
            && self.heap_start < buffer_end
        {
            return false;
        }
        if self.stack_bottom != 0
            && self.stack_top != 0
            && buffer.virt_start < self.stack_top
            && self.stack_bottom < buffer_end
        {
            return false;
        }
        self.dma_buffers.push(buffer);
        true
    }

    pub fn remove_dma_buffer(&mut self, handle: u64) -> Option<DmaBuffer> {
        let idx = self
            .dma_buffers
            .iter()
            .position(|buf| buf.handle == handle)?;
        Some(self.dma_buffers.remove(idx))
    }

    pub fn take_dma_buffers(&mut self) -> Vec<DmaBuffer> {
        core::mem::take(&mut self.dma_buffers)
    }

    pub fn find_dma_buffer_by_addr(&self, addr: u64, len: u64) -> Option<&DmaBuffer> {
        let end = addr.checked_add(len)?;
        self.dma_buffers.iter().find(|buf| {
            let Some(buf_end) = buf.end() else {
                return false;
            };
            addr < buf_end && buf.virt_start < end
        })
    }

    pub fn object_handles(&self) -> &ObjectHandleTable {
        &self.object_handles
    }

    pub fn object_handles_mut(&mut self) -> &mut ObjectHandleTable {
        &mut self.object_handles
    }

    pub fn clone_object_handles(&self) -> alloc::boxed::Box<ObjectHandleTable> {
        alloc::boxed::Box::new((*self.object_handles).clone())
    }

    pub fn set_object_handles(&mut self, table: alloc::boxed::Box<ObjectHandleTable>) {
        self.object_handles = table;
    }

    pub fn launch_context(&self) -> &LaunchContext {
        &self.launch_context
    }

    pub fn launch_context_mut(&mut self) -> &mut LaunchContext {
        &mut self.launch_context
    }

    pub fn set_launch_context(&mut self, context: alloc::boxed::Box<LaunchContext>) {
        self.launch_context = context;
    }

    pub fn clone_launch_context(&self) -> alloc::boxed::Box<LaunchContext> {
        alloc::boxed::Box::new((*self.launch_context).clone())
    }

    /// Drops object handles which were not explicitly selected for the next
    /// process image. Launch-context keys remain opaque to the kernel.
    pub fn retain_launch_context_handles_for_exec(&mut self) {
        let launch_context = &self.launch_context;
        self.object_handles
            .retain(|handle| launch_context.references_handle(handle));
    }
}

fn regions_overlap(a: &MemoryRegion, b: &MemoryRegion) -> bool {
    let (Some(a_end), Some(b_end)) = (a.end(), b.end()) else {
        return true;
    };
    a.start < b_end && b.start < a_end
}

impl core::fmt::Debug for Process {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("Process");
        debug_struct
            .field("id", &self.id)
            .field("application_identity", &self.application_identity)
            .field("name", &self.name())
            .field("state", &self.state)
            .field("privilege", &self.privilege)
            .field("capabilities", &self.capabilities)
            .field("priority", &self.priority)
            .field("exit_code", &self.exit_code);

        if let Some(pt) = self.page_table {
            debug_struct.field("page_table", &format_args!("{:#x}", pt));
        } else {
            debug_struct.field("page_table", &None::<u64>);
        }

        debug_struct.finish()
    }
}

/// プロセステーブル
///
/// システム内のすべてのプロセスを管理する
pub struct ProcessTable {
    /// プロセスの配列（最大容量）
    processes: [Option<Process>; Self::MAX_PROCESSES],
    /// 現在のプロセス数
    count: usize,
}

impl ProcessTable {
    /// プロセステーブルの最大容量
    pub const MAX_PROCESSES: usize = 64;

    /// 新しいプロセステーブルを作成
    pub const fn new() -> Self {
        const INIT: Option<Process> = None;
        Self {
            processes: [INIT; Self::MAX_PROCESSES],
            count: 0,
        }
    }

    /// プロセスを追加
    ///
    /// # Returns
    /// 成功時はプロセスIDを返す。テーブルが満杯の場合はNone
    pub fn add(&mut self, process: Process) -> Option<ProcessId> {
        if self.count >= Self::MAX_PROCESSES {
            return None;
        }

        let id = process.id();

        // 空きスロットを探す
        for slot in &mut self.processes {
            if slot.is_none() {
                *slot = Some(process);
                self.count += 1;
                return Some(id);
            }
        }

        None
    }

    /// プロセスIDでプロセスを取得
    pub fn get(&self, id: ProcessId) -> Option<&Process> {
        self.processes
            .iter()
            .find_map(|slot| slot.as_ref().filter(|p| p.id() == id))
    }

    /// プロセスIDでプロセスの可変参照を取得
    pub fn get_mut(&mut self, id: ProcessId) -> Option<&mut Process> {
        self.processes
            .iter_mut()
            .find_map(|slot| slot.as_mut().filter(|p| p.id() == id))
    }

    /// プロセスを削除
    ///
    /// # Returns
    /// 削除されたプロセスを返す。存在しない場合はNone
    pub fn remove(&mut self, id: ProcessId) -> Option<Process> {
        for slot in &mut self.processes {
            if let Some(ref process) = slot {
                if process.id() == id {
                    self.count -= 1;
                    return slot.take();
                }
            }
        }
        None
    }

    /// すべてのプロセスを反復処理
    pub fn iter(&self) -> impl Iterator<Item = &Process> {
        self.processes.iter().filter_map(|slot| slot.as_ref())
    }

    /// すべてのプロセスを可変反復処理
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Process> {
        self.processes.iter_mut().filter_map(|slot| slot.as_mut())
    }

    /// 名前でプロセスを検索
    pub fn find_by_name(&self, name: &str) -> Option<&Process> {
        // 名前比較: まず完全一致を試し、それでも見つからない場合はいくつかの互換候補を試す。
        // マッチ順序:
        // 1. 完全一致
        // 2. stored_name without ".elf" == name
        // 3. stored_name == name + ".elf"
        // 4. 起動ポリシーに定義された alias == name
        // 5. stored_name contains name as substring (fallback)

        // 1) 完全一致
        if let Some(p) = self
            .processes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| p.name() == name)
        {
            return Some(p);
        }

        // 2) stored without .elf
        if let Some(p) = self.processes.iter().filter_map(|s| s.as_ref()).find(|p| {
            p.name()
                .strip_suffix(".elf")
                .map(|s| s == name)
                .unwrap_or(false)
        }) {
            return Some(p);
        }

        // 3) stored == name + .elf
        let mut name_elf = String::new();
        name_elf.push_str(name);
        name_elf.push_str(".elf");
        if let Some(p) = self
            .processes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| p.name() == name_elf)
        {
            return Some(p);
        }

        // 4) executable path alias lookup (path -> alias)
        if let Some(alias) = process_alias_for_executable(name) {
            if let Some(p) = self
                .processes
                .iter()
                .filter_map(|s| s.as_ref())
                .find(|p| p.name() == alias || p.name() == format!("{}.elf", alias))
            {
                return Some(p);
            }
        }

        // 5) fallback: substring match
        self.processes
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|p| p.name().contains(name))
    }

    fn take_exited(&mut self, id: ProcessId) -> Option<Process> {
        for slot in &mut self.processes {
            let should_reclaim = slot.as_ref().is_some_and(|process| {
                process.id() == id && process.state() == ProcessState::Zombie
            });
            if should_reclaim {
                self.count = self.count.saturating_sub(1);
                return slot.take();
            }
        }
        None
    }

    /// 現在のプロセス数を取得
    pub fn count(&self) -> usize {
        self.count
    }
}

pub(crate) fn process_alias_for_executable(path: &str) -> Option<String> {
    let aliases_path = crate::config::kernel().policy_paths.process_aliases()?;
    let data = crate::cext::fs::read_all(aliases_path)?;
    let text = core::str::from_utf8(&data).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((alias, driver_path)) = line.split_once('=') else {
            continue;
        };
        if driver_path.trim() == path {
            let alias = alias.trim();
            if !alias.is_empty() {
                return Some(alias.to_string());
            }
        }
    }
    None
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

/// グローバルプロセステーブル
static PROCESS_TABLE: SpinLock<ProcessTable> = SpinLock::new(ProcessTable::new());
const MAX_PROCESS_EXIT_WAITERS: usize = super::ThreadQueue::MAX_THREADS;

struct ProcessExitWaiter {
    thread: super::ThreadId,
    processes: Vec<ProcessId>,
}

static PROCESS_EXIT_WAITERS: SpinLock<[Option<ProcessExitWaiter>; MAX_PROCESS_EXIT_WAITERS]> =
    SpinLock::new([const { None }; MAX_PROCESS_EXIT_WAITERS]);
static DEFERRED_PROCESS_RECLAIMS: SpinLock<[Option<ProcessId>; ProcessTable::MAX_PROCESSES]> =
    SpinLock::new([None; ProcessTable::MAX_PROCESSES]);

fn defer_process_reclaim(process: ProcessId) {
    let mut deferred = DEFERRED_PROCESS_RECLAIMS.lock();
    if deferred
        .iter()
        .flatten()
        .any(|candidate| *candidate == process)
    {
        return;
    }
    if let Some(slot) = deferred.iter_mut().find(|slot| slot.is_none()) {
        *slot = Some(process);
    } else {
        crate::audit::log(
            crate::audit::AuditEventKind::Fault,
            "deferred process reclaim queue is full",
        );
    }
}

pub fn register_process_exit_waiter(thread: super::ThreadId, process: ProcessId) -> bool {
    let mut waiters = PROCESS_EXIT_WAITERS.lock();
    if let Some(waiter) = waiters
        .iter_mut()
        .flatten()
        .find(|waiter| waiter.thread == thread)
    {
        if !waiter.processes.contains(&process) {
            waiter.processes.push(process);
        }
        return true;
    }
    let Some(slot) = waiters.iter_mut().find(|slot| slot.is_none()) else {
        return false;
    };
    *slot = Some(ProcessExitWaiter {
        thread,
        processes: alloc::vec![process],
    });
    true
}

pub fn remove_process_exit_waiters(thread: super::ThreadId) {
    let mut waiters = PROCESS_EXIT_WAITERS.lock();
    for slot in waiters.iter_mut() {
        if slot.as_ref().is_some_and(|waiter| waiter.thread == thread) {
            *slot = None;
        }
    }
}

pub fn remove_process_exit_waiter(thread: super::ThreadId, process: ProcessId) {
    let mut waiters = PROCESS_EXIT_WAITERS.lock();
    for slot in waiters.iter_mut() {
        if let Some(waiter) = slot {
            if waiter.thread != thread {
                continue;
            }
            waiter.processes.retain(|candidate| *candidate != process);
            if waiter.processes.is_empty() {
                *slot = None;
            }
        }
    }
}

fn wake_process_exit_waiters(process: ProcessId) {
    let mut wake = [None; MAX_PROCESS_EXIT_WAITERS];
    let mut count = 0usize;
    {
        let mut waiters = PROCESS_EXIT_WAITERS.lock();
        for slot in waiters.iter_mut() {
            if slot
                .as_ref()
                .is_some_and(|waiter| waiter.processes.contains(&process))
            {
                if count < wake.len() {
                    if let Some(waiter) = slot.as_ref() {
                        wake[count] = Some(waiter.thread);
                        count += 1;
                    }
                }
                *slot = None;
            }
        }
    }
    for thread in wake.into_iter().take(count).flatten() {
        crate::task::wake_registered_waiter(thread);
    }
}

/// プロセステーブルにプロセスを追加
pub fn add_process(process: Process) -> Option<ProcessId> {
    PROCESS_TABLE.lock().add(process)
}

/// プロセスを削除
pub fn remove_process(id: ProcessId) -> Option<Process> {
    crate::capability::path::revoke_scoped_paths(id.as_u64());
    release_process_mmio_mappings(id);
    release_process_dma_buffers(id);
    PROCESS_TABLE.lock().remove(id)
}

/// プロセスIDでプロセス情報を取得（読み取り専用操作）
pub fn with_process<F, R>(id: ProcessId, f: F) -> Option<R>
where
    F: FnOnce(&Process) -> R,
{
    let table = PROCESS_TABLE.lock();
    table.get(id).map(f)
}

/// プロセスIDでプロセス情報を可変操作
pub fn with_process_mut<F, R>(id: ProcessId, f: F) -> Option<R>
where
    F: FnOnce(&mut Process) -> R,
{
    let mut table = PROCESS_TABLE.lock();
    table.get_mut(id).map(f)
}

/// 名前からプロセスIDを検索
pub fn find_process_id_by_name(name: &str) -> Option<ProcessId> {
    let table = PROCESS_TABLE.lock();
    table.find_by_name(name).map(|p| p.id())
}

/// すべてのプロセスに対して処理を実行
pub fn for_each_process<F>(mut f: F)
where
    F: FnMut(&Process),
{
    let table = PROCESS_TABLE.lock();
    for process in table.iter() {
        f(process);
    }
}

/// プロセスを終了状態（Zombie）へ遷移させる
pub fn mark_process_exited(id: ProcessId, exit_code: u64) {
    {
        let mut table = PROCESS_TABLE.lock();
        let Some(proc) = table.get_mut(id) else {
            return;
        };
        proc.mark_exited(exit_code);
    }
    wake_process_exit_waiters(id);
    defer_process_reclaim(id);
}

fn destroy_exited_process(mut process: Process) -> (ProcessId, u64) {
    let pid = process.id();
    let exit_code = process.exit_code().unwrap_or(0);
    let page_table = if process.page_table_owned() {
        process.page_table()
    } else {
        None
    };
    let mmio_mappings = process.take_mmio_mappings();
    let dma_buffers = process.take_dma_buffers();
    crate::capability::path::revoke_scoped_paths(pid.as_u64());
    if let Some(table_phys) = page_table {
        for mmio in &mmio_mappings {
            let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
                table_phys,
                mmio.virt_start(),
                mmio.len(),
            );
        }
        for dma in &dma_buffers {
            let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
                table_phys,
                dma.virt_start(),
                dma.len(),
            );
        }
    }
    for dma in dma_buffers {
        for page_index in 0..dma.page_count() {
            let phys = dma.phys_start() + (page_index as u64) * 4096;
            let frame = x86_64::structures::paging::PhysFrame::containing_address(
                x86_64::PhysAddr::new(phys),
            );
            let _ = crate::mem::frame::deallocate_frame(frame);
        }
    }
    if let Some(table_phys) = page_table {
        if let Err(e) = crate::mem::paging::destroy_user_page_table(table_phys) {
            crate::warn!(
                "Failed to destroy child page table while reaping pid={:?}: {:?}",
                pid,
                e
            );
        }
    }
    (pid, exit_code)
}

/// Reclaims exited execution records from a context which is
/// not running on the reclaimed process's address space. ProcessHandle state
/// remains available through its shared `ProcessObject`.
pub fn flush_deferred_process_reclaims() {
    let current = crate::syscall::security::current_process_id();
    let mut pending = [None; ProcessTable::MAX_PROCESSES];
    {
        let mut deferred = DEFERRED_PROCESS_RECLAIMS.lock();
        core::mem::swap(&mut *deferred, &mut pending);
    }
    for process_id in pending.into_iter().flatten() {
        if current == Some(process_id) {
            defer_process_reclaim(process_id);
            continue;
        }
        let mut has_threads = false;
        crate::task::for_each_thread(|thread| {
            if thread.process_id() == process_id {
                has_threads = true;
            }
        });
        if has_threads {
            defer_process_reclaim(process_id);
            continue;
        }
        let process = PROCESS_TABLE.lock().take_exited(process_id);
        if let Some(process) = process {
            let _ = destroy_exited_process(process);
        }
    }
}

pub fn release_process_mmio_mappings(pid: ProcessId) {
    let (page_table, mmio_mappings) = match with_process_mut(pid, |proc| {
        let page_table = proc.page_table();
        let mmio_mappings = proc.take_mmio_mappings();
        (page_table, mmio_mappings)
    }) {
        Some((page_table, mmio_mappings)) => (page_table, mmio_mappings),
        None => return,
    };

    if let Some(table_phys) = page_table {
        for mmio in &mmio_mappings {
            let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
                table_phys,
                mmio.virt_start(),
                mmio.len(),
            );
        }
    }
}

pub fn release_process_dma_buffers(pid: ProcessId) {
    let (page_table, dma_buffers) = match with_process_mut(pid, |proc| {
        let page_table = proc.page_table();
        let dma_buffers = proc.take_dma_buffers();
        proc.reset_dma_arena();
        (page_table, dma_buffers)
    }) {
        Some((page_table, dma_buffers)) => (page_table, dma_buffers),
        None => return,
    };

    if let Some(table_phys) = page_table {
        for dma in &dma_buffers {
            let _ = crate::mem::paging::unmap_range_in_table_preserve_frames(
                table_phys,
                dma.virt_start(),
                dma.len(),
            );
        }
    }

    for dma in dma_buffers {
        for page_index in 0..dma.page_count() {
            let phys = dma.phys_start() + (page_index as u64) * 4096;
            let frame = x86_64::structures::paging::PhysFrame::containing_address(
                x86_64::PhysAddr::new(phys),
            );
            let _ = crate::mem::frame::deallocate_frame(frame);
        }
    }
}

/// 現在のプロセス数を取得
pub fn process_count() -> usize {
    PROCESS_TABLE.lock().count()
}

/// プロセス生成時に capability を設定する（カーネル内部用）
///
/// これは syscall として公開してはいけない。
/// ユーザープロセスがこれを呼べると、自己昇格で sandbox を回避できるため。
pub fn set_process_capabilities(pid: ProcessId, caps: CapabilitySet) -> Result<()> {
    let updated = with_process_mut(pid, |proc| {
        proc.capabilities = caps;
    })
    .is_some();

    if updated {
        Ok(())
    } else {
        Err(Kernel::Process(ProcessError::ProcessNotFound))
    }
}

/// プロセスが指定 capability を持つか（階層継承を含む）
pub fn process_has_capability(pid: ProcessId, cap: crate::capability::Capability) -> bool {
    with_process(pid, |proc| proc.capabilities.contains(cap)).unwrap_or(false)
}

pub fn process_has_kernel_authority(
    pid: ProcessId,
    authority: &crate::capability::KernelAuthority,
) -> bool {
    with_process(pid, |proc| proc.has_kernel_authority(authority)).unwrap_or(false)
}

pub fn process_has_kernel_capability_authority(
    pid: ProcessId,
    capability: crate::capability::KernelCapability,
) -> bool {
    with_process(pid, |proc| proc.has_kernel_capability_authority(capability)).unwrap_or(false)
}
