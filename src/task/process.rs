use crate::interrupt::spinlock::SpinLock;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;

use crate::capability::CapabilitySet;
use crate::result::{Kernel, Process as ProcessError, Result};

use super::fd_table::FdTable;
use super::ids::{PrivilegeLevel, ProcessId, ProcessState};
use super::signal::SignalState;

/// プロセス単位の resource limit
#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_threads: usize,
    pub max_fds: usize,
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
            max_fds: super::fd_table::PROCESS_MAX_FDS,
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
pub enum MmapBacking {
    Anonymous {
        data: alloc::vec::Vec<u8>,
        writable: bool,
        shared: bool,
    },
    File {
        path: String,
        data: alloc::vec::Vec<u8>,
        writable: bool,
        shared: bool,
    },
}

#[derive(Clone, Debug)]
pub struct MmapRegion {
    start: u64,
    len: u64,
    prot: u64,
    flags: u64,
    backing: MmapBacking,
    dirty_pages: alloc::vec::Vec<u64>,
}

impl MmapRegion {
    pub fn file_backed(
        start: u64,
        len: u64,
        prot: u64,
        flags: u64,
        path: String,
        data: alloc::vec::Vec<u8>,
        writable: bool,
        shared: bool,
    ) -> Self {
        Self {
            start,
            len,
            prot,
            flags,
            backing: MmapBacking::File {
                path,
                data,
                writable,
                shared,
            },
            dirty_pages: alloc::vec::Vec::new(),
        }
    }

    pub fn anonymous(
        start: u64,
        len: u64,
        prot: u64,
        flags: u64,
        data: alloc::vec::Vec<u8>,
        writable: bool,
        shared: bool,
    ) -> Self {
        Self {
            start,
            len,
            prot,
            flags,
            backing: MmapBacking::Anonymous {
                data,
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

    pub fn backing(&self) -> &MmapBacking {
        &self.backing
    }

    pub fn backing_mut(&mut self) -> &mut MmapBacking {
        &mut self.backing
    }

    pub fn set_shared(&mut self, shared: bool) {
        if shared {
            self.flags |= 0x1;
        } else {
            self.flags &= !0x1;
        }
        match &mut self.backing {
            MmapBacking::Anonymous { shared: s, .. } => *s = shared,
            MmapBacking::File { shared: s, .. } => *s = shared,
        }
    }

    pub fn set_writable(&mut self, writable: bool) {
        match &mut self.backing {
            MmapBacking::Anonymous { writable: w, .. } => *w = writable,
            MmapBacking::File { writable: w, .. } => *w = writable,
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

    pub fn dirty_pages(&self) -> &[u64] {
        &self.dirty_pages
    }

    pub fn is_writable(&self) -> bool {
        (self.prot & 0x2) != 0
    }

    pub fn is_shared(&self) -> bool {
        (self.flags & 0x1) != 0
    }
}

impl MmapBacking {
    pub fn file_path(&self) -> &str {
        match self {
            MmapBacking::Anonymous { .. } => "",
            MmapBacking::File { path, .. } => path.as_str(),
        }
    }

    pub fn file_data(&self) -> &[u8] {
        match self {
            MmapBacking::Anonymous { data, .. } => data.as_slice(),
            MmapBacking::File { data, .. } => data.as_slice(),
        }
    }

    pub fn file_data_mut(&mut self) -> &mut alloc::vec::Vec<u8> {
        match self {
            MmapBacking::Anonymous { data, .. } => data,
            MmapBacking::File { data, .. } => data,
        }
    }

    pub fn file_writable(&self) -> bool {
        match self {
            MmapBacking::Anonymous { writable, .. } => *writable,
            MmapBacking::File { writable, .. } => *writable,
        }
    }

    pub fn file_shared(&self) -> bool {
        match self {
            MmapBacking::Anonymous { shared, .. } => *shared,
            MmapBacking::File { shared, .. } => *shared,
        }
    }
}

/// プロセス構造体
///
/// メモリ空間とリソースを管理する実行単位。
/// 1つ以上のスレッドを持つ。
pub struct Process {
    /// プロセスID
    id: ProcessId,
    /// アプリID（アプリの場合のみ設定）
    app_id: Option<String>,
    /// サービスID（サービスの場合のみ設定）
    service_id: Option<String>,
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
    /// 親プロセスID（存在する場合）
    parent_id: Option<ProcessId>,
    /// ページテーブルのアドレス（メモリ空間）。Noneの場合はカーネル空間を共有。
    page_table: Option<u64>,
    /// page_table をこの Process が所有しているかどうか
    page_table_owned: bool,
    /// ヒープ開始アドレス
    heap_start: u64,
    /// 現在のヒープ終了アドレス (program break)
    heap_end: u64,
    /// ユーザースタックの現在の最低マップアドレス（下向きに伸びる）
    stack_bottom: u64,
    /// ユーザースタックのトップアドレス（初期 RSP 付近）
    stack_top: u64,
    /// カレントワーキングディレクトリ（固定バッファ、ヒープ確保不要）
    cwd: [u8; 256],
    cwd_len: usize,
    /// 実行ファイルのパス
    exe_path: String,
    /// 優先度（0が最高、値が大きいほど低い）
    priority: u8,
    /// 前景プロセスとして待ち時間を優先する
    foreground: bool,
    /// 終了コード（生存中はNone）
    exit_code: Option<u64>,
    /// プロセスグループID（0 = 自身の PID と同じ）
    pgid: u64,
    /// セッションID（0 = 自身の PID と同じ）
    sid: u64,
    /// シグナル状態（ハンドラ・マスク・pending）— ヒープに置いてスタック消費を抑える
    signal_state: alloc::boxed::Box<SignalState>,
    /// プロセスごとのファイルディスクリプタテーブル — ヒープに置いてスタック消費を抑える
    fd_table: alloc::boxed::Box<FdTable>,
    /// file-backed mmap の VMA テーブル
    mmap_regions: alloc::vec::Vec<MmapRegion>,
    /// プロセスごとの resource limit
    resource_limits: ResourceLimits,
}

impl Process {
    /// 新しいプロセスを作成
    ///
    /// # Arguments
    /// * `name` - プロセス名
    /// * `privilege` - 権限レベル
    /// * `parent_id` - 親プロセスID
    /// * `priority` - プロセスの優先度
    pub fn new(
        name: &str,
        privilege: PrivilegeLevel,
        parent_id: Option<ProcessId>,
        priority: u8,
    ) -> Self {
        let mut name_buf = [0u8; 32];
        let bytes = name.as_bytes();
        let len = core::cmp::min(bytes.len(), 32);
        name_buf[..len].copy_from_slice(&bytes[..len]);

        // デフォルトのヒープ領域（仮）。exec時に再設定されるべき。
        // 0x40000000番地あたりを開始にする例が多いが、ここでは0にしておく。
        let heap_start = 0;

        Self {
            id: ProcessId::new(),
            app_id: None,
            service_id: None,
            name: name_buf,
            name_len: len,
            state: ProcessState::Running,
            privilege,
            capabilities: CapabilitySet::empty(),
            parent_id,
            page_table: None, // TODO: ページテーブル実装後に設定
            page_table_owned: true,
            heap_start,
            heap_end: heap_start,
            stack_bottom: 0,
            stack_top: 0,
            cwd: {
                let mut b = [0u8; 256];
                b[0] = b'/';
                b
            },
            cwd_len: 1,
            exe_path: String::new(),
            priority,
            foreground: false,
            exit_code: None,
            pgid: 0,
            sid: 0,
            signal_state: alloc::boxed::Box::new(SignalState::new()),
            fd_table: FdTable::new_boxed(),
            mmap_regions: alloc::vec::Vec::new(),
            resource_limits: ResourceLimits::default(),
        }
    }

    /// プロセスIDを取得
    pub fn id(&self) -> ProcessId {
        self.id
    }

    /// アプリIDを取得
    pub fn app_id(&self) -> Option<&str> {
        self.app_id.as_deref()
    }

    /// サービスIDを取得
    pub fn service_id(&self) -> Option<&str> {
        self.service_id.as_deref()
    }

    /// サービスIDを設定する（カーネル内部用）
    pub(crate) fn set_service_id<S: Into<String>>(&mut self, service_id: S) {
        self.service_id = Some(service_id.into());
    }

    /// capability 集合を取得（読み取り専用）
    pub fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    /// capability 集合を可変取得（kernel 内部用）
    pub(crate) fn capabilities_mut(&mut self) -> &mut CapabilitySet {
        &mut self.capabilities
    }

    /// exec 経路でプロセス生成時に capability を設定する（カーネル内部用）
    ///
    /// # 注意
    /// capability は sandbox の根幹なので、ユーザー空間へ公開しないこと。
    pub(crate) fn set_capabilities_for_exec(&mut self, caps: CapabilitySet) {
        self.capabilities = caps;
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

    /// 親プロセスIDを取得
    pub fn parent_id(&self) -> Option<ProcessId> {
        self.parent_id
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

    pub fn stack_bottom(&self) -> u64 {
        self.stack_bottom
    }
    pub fn stack_top(&self) -> u64 {
        self.stack_top
    }
    pub fn set_stack_bottom(&mut self, addr: u64) {
        self.stack_bottom = addr;
    }
    pub fn set_stack_top(&mut self, addr: u64) {
        self.stack_top = addr;
    }

    pub fn cwd(&self) -> &str {
        core::str::from_utf8(&self.cwd[..self.cwd_len]).unwrap_or("/")
    }

    pub fn set_cwd(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(255);
        self.cwd[..len].copy_from_slice(&bytes[..len]);
        self.cwd_len = len;
    }

    pub fn exe_path(&self) -> &str {
        &self.exe_path
    }

    pub fn set_exe_path(&mut self, path: &str) {
        self.exe_path.clear();
        self.exe_path.push_str(path);
    }

    /// シグナル状態への読み取りアクセス
    pub fn signal_state(&self) -> &SignalState {
        &self.signal_state
    }

    /// シグナル状態への可変アクセス
    pub fn signal_state_mut(&mut self) -> &mut SignalState {
        &mut self.signal_state
    }

    /// FD テーブルへの読み取りアクセス
    pub fn fd_table(&self) -> &FdTable {
        &self.fd_table
    }

    /// FD テーブルへの可変アクセス
    pub fn fd_table_mut(&mut self) -> &mut FdTable {
        &mut self.fd_table
    }

    pub fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }

    pub fn set_resource_limits(&mut self, limits: ResourceLimits) {
        self.resource_limits = limits;
    }

    pub fn mmap_regions(&self) -> &[MmapRegion] {
        &self.mmap_regions
    }

    pub fn mmap_regions_mut(&mut self) -> &mut alloc::vec::Vec<MmapRegion> {
        &mut self.mmap_regions
    }

    pub fn set_mmap_regions(&mut self, regions: alloc::vec::Vec<MmapRegion>) {
        self.mmap_regions = regions;
    }

    pub fn add_mmap_region(&mut self, region: MmapRegion) -> bool {
        let overlaps = self
            .mmap_regions
            .iter()
            .any(|existing| regions_overlap(existing, &region));
        if overlaps {
            return false;
        }
        self.mmap_regions.push(region);
        true
    }

    pub fn find_mmap_region(&self, addr: u64) -> Option<&MmapRegion> {
        self.mmap_regions
            .iter()
            .find(|region| region.contains(addr))
    }

    pub fn find_mmap_region_mut(&mut self, addr: u64) -> Option<&mut MmapRegion> {
        self.mmap_regions
            .iter_mut()
            .find(|region| region.contains(addr))
    }

    pub fn remove_mmap_region(&mut self, start: u64, len: u64) -> Option<MmapRegion> {
        let end = start.checked_add(len)?;
        let idx = self
            .mmap_regions
            .iter()
            .position(|region| region.start == start && region.end() == Some(end))?;
        Some(self.mmap_regions.remove(idx))
    }

    /// fork 用: FD テーブルをクローンして新しい Box を返す
    pub fn clone_fd_table_for_fork(&self) -> alloc::boxed::Box<FdTable> {
        self.fd_table.clone_for_fork()
    }

    pub fn clone_mmap_regions_for_fork(&self) -> alloc::vec::Vec<MmapRegion> {
        self.mmap_regions.clone()
    }

    /// FD テーブルを差し替える（fork の子プロセス初期化で使用）
    pub fn set_fd_table(&mut self, table: alloc::boxed::Box<FdTable>) {
        self.fd_table = table;
    }

    /// プロセスグループ ID を取得（0 は自身の PID を意味する）
    pub fn pgid(&self) -> u64 {
        if self.pgid == 0 {
            self.id.as_u64()
        } else {
            self.pgid
        }
    }

    /// プロセスグループ ID を設定
    pub fn set_pgid(&mut self, pgid: u64) {
        self.pgid = pgid;
    }

    /// セッション ID を取得（0 は自身の PID を意味する）
    pub fn sid(&self) -> u64 {
        if self.sid == 0 {
            self.id.as_u64()
        } else {
            self.sid
        }
    }

    /// セッション ID を設定
    pub fn set_sid(&mut self, sid: u64) {
        self.sid = sid;
    }
}

fn regions_overlap(a: &MmapRegion, b: &MmapRegion) -> bool {
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
            .field("app_id", &self.app_id)
            .field("service_id", &self.service_id)
            .field("name", &self.name())
            .field("state", &self.state)
            .field("privilege", &self.privilege)
            .field("parent_id", &self.parent_id)
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
        // 4. drivers.list に定義された alias == name
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

        // 4) drivers.list alias lookup (path -> alias)
        if let Some(alias) = driver_alias_for_path(name) {
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

    fn is_child_match(process: &Process, parent: ProcessId, target: Option<ProcessId>) -> bool {
        if process.parent_id() != Some(parent) {
            return false;
        }
        if let Some(target_id) = target {
            process.id() == target_id
        } else {
            true
        }
    }

    /// 対象に一致する子プロセスが存在するかを返す
    pub fn has_child(&self, parent: ProcessId, target: Option<ProcessId>) -> bool {
        self.processes
            .iter()
            .filter_map(|slot| slot.as_ref())
            .any(|p| Self::is_child_match(p, parent, target))
    }

    /// ゾンビ子プロセスを1つ回収する
    pub fn reap_zombie_child(
        &mut self,
        parent: ProcessId,
        target: Option<ProcessId>,
    ) -> Option<(ProcessId, u64, Option<u64>)> {
        for slot in &mut self.processes {
            let should_reap = slot.as_ref().is_some_and(|proc| {
                Self::is_child_match(proc, parent, target) && proc.state() == ProcessState::Zombie
            });
            if !should_reap {
                continue;
            }

            if let Some(proc) = slot.take() {
                let pid = proc.id();
                let exit_code = proc.exit_code().unwrap_or(0);
                let page_table = if proc.page_table_owned() {
                    proc.page_table()
                } else {
                    None
                };
                self.count = self.count.saturating_sub(1);
                return Some((pid, exit_code, page_table));
            }
        }
        None
    }

    /// 現在のプロセス数を取得
    pub fn count(&self) -> usize {
        self.count
    }
}

pub(crate) fn driver_alias_for_path(path: &str) -> Option<String> {
    let data = crate::cext::fs::read_all("/config/drivers.list")?;
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

/// プロセステーブルにプロセスを追加
pub fn add_process(process: Process) -> Option<ProcessId> {
    PROCESS_TABLE.lock().add(process)
}

/// プロセスを削除
pub fn remove_process(id: ProcessId) -> Option<Process> {
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
    let mut table = PROCESS_TABLE.lock();
    if let Some(proc) = table.get_mut(id) {
        proc.mark_exited(exit_code);
    }
}

/// 一致する子プロセスが存在するか確認する
pub fn has_child_process(parent: ProcessId, target: Option<ProcessId>) -> bool {
    PROCESS_TABLE.lock().has_child(parent, target)
}

/// 一致するゾンビ子プロセスを回収する
pub fn reap_zombie_child_process(
    parent: ProcessId,
    target: Option<ProcessId>,
) -> Option<(ProcessId, u64)> {
    let (pid, exit_code, page_table) = PROCESS_TABLE.lock().reap_zombie_child(parent, target)?;
    if let Some(table_phys) = page_table {
        if let Err(e) = crate::mem::paging::destroy_user_page_table(table_phys) {
            crate::warn!(
                "Failed to destroy child page table while reaping pid={:?}: {:?}",
                pid,
                e
            );
        }
    }
    Some((pid, exit_code))
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
