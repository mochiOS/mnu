//! cext 境界の共通定義
//!
//! fs や disk のような実装は kernel ではなく cext として扱う。
//! このモジュールは、cext の登録・停止・endpoint・resource limit を束ねる
//! 最小の信頼基盤を表す。

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::string::ToString;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use crate::task::ResourceLimits;

pub mod disk;
pub mod fs;

/// cext の種類
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CextKind {
    Filesystem,
    BlockDevice,
    DeviceService,
    Other,
}

/// cext インスタンス
#[derive(Clone, Debug)]
pub struct CextInstance {
    pub id: u64,
    pub name: String,
    pub kind: CextKind,
    pub process_id: Option<u64>,
    pub endpoint: Option<crate::syscall::ipc::IpcEndpoint>,
    pub limits: ResourceLimits,
    pub loaded: bool,
}

static NEXT_CEXT_ID: AtomicU64 = AtomicU64::new(1);
static CEXT_REGISTRY: Mutex<Option<BTreeMap<u64, CextInstance>>> = Mutex::new(None);

fn with_registry_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, CextInstance>) -> R) -> R {
    let mut guard = CEXT_REGISTRY.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub fn load_cext(name: &str, kind: CextKind, process_id: Option<u64>) -> u64 {
    let id = NEXT_CEXT_ID.fetch_add(1, Ordering::Relaxed);
    let instance = CextInstance {
        id,
        name: name.to_string(),
        kind,
        process_id,
        endpoint: None,
        limits: ResourceLimits::default(),
        loaded: true,
    };
    with_registry_mut(|registry| {
        registry.insert(id, instance);
    });
    id
}

pub fn register_endpoint(id: u64, endpoint: crate::syscall::ipc::IpcEndpoint) -> bool {
    with_registry_mut(|registry| {
        let Some(instance) = registry.get_mut(&id) else {
            return false;
        };
        instance.endpoint = Some(endpoint);
        true
    })
}

pub fn endpoint_for(id: u64) -> Option<crate::syscall::ipc::IpcEndpoint> {
    with_registry_mut(|registry| registry.get(&id).and_then(|instance| instance.endpoint))
}

pub fn revoke(id: u64) -> bool {
    with_registry_mut(|registry| {
        if let Some(instance) = registry.get_mut(&id) {
            instance.loaded = false;
            instance.endpoint = None;
            true
        } else {
            false
        }
    })
}

pub fn unregister(id: u64) -> bool {
    with_registry_mut(|registry| registry.remove(&id).is_some())
}

#[inline]
pub fn init_runtime_config() {
    let _ = crate::config::kernel().cext;
}

#[inline]
pub fn load_modules() {
    let _ = fs::is_loaded();
}
