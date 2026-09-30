//! Filesystem object model shared by file descriptors and filesystem backends.

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::interrupt::spinlock::SpinLock;

pub mod userspace;

/// Identifies a mounted filesystem instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MountId(pub u64);

/// Identifies a filesystem provider instance independently of its mount point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilesystemId(pub u64);

/// Identifies an inode inside a mounted filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InodeId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VnodeKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// Filesystem-stable object identity. Backends own metadata and file contents.
pub struct Inode {
    pub mount_id: MountId,
    pub inode_id: InodeId,
    pub kind: VnodeKind,
}

/// Transitional backend reference used while the path-based CExt ABI is active.
///
/// A userspace filesystem server will replace this with an opaque server handle;
/// callers already consume a `Vnode` and do not need another FD model change.
pub enum VnodeBacking {
    LegacyPath(String),
    CextHandle {
        path: String,
        handle: u64,
    },
    UserspaceHandle {
        path: String,
        node_id: u64,
        open_id: u64,
    },
}

/// A resolved filesystem object kept alive independently of a descriptor number.
pub struct Vnode {
    pub inode: Arc<Inode>,
    backing: VnodeBacking,
}

impl Vnode {
    pub fn legacy_path(path: String, kind: VnodeKind) -> Self {
        Self::legacy_path_on(MountId(1), path, kind)
    }

    pub fn legacy_path_on(mount_id: MountId, path: String, kind: VnodeKind) -> Self {
        Self {
            inode: Arc::new(Inode {
                mount_id,
                inode_id: InodeId(legacy_inode_id(&path)),
                kind,
            }),
            backing: VnodeBacking::LegacyPath(path),
        }
    }

    pub fn cext_handle(mount_id: MountId, path: String, handle: u64, kind: VnodeKind) -> Self {
        Self {
            inode: Arc::new(Inode {
                mount_id,
                inode_id: InodeId(legacy_inode_id(&path)),
                kind,
            }),
            backing: VnodeBacking::CextHandle { path, handle },
        }
    }

    pub fn userspace_handle(
        mount_id: MountId,
        inode_id: InodeId,
        path: String,
        open_id: u64,
        kind: VnodeKind,
    ) -> Self {
        Self {
            inode: Arc::new(Inode {
                mount_id,
                inode_id,
                kind,
            }),
            backing: VnodeBacking::UserspaceHandle {
                path,
                node_id: inode_id.0,
                open_id,
            },
        }
    }

    pub fn path(&self) -> &str {
        match &self.backing {
            VnodeBacking::LegacyPath(path) => path,
            VnodeBacking::CextHandle { path, .. } => path,
            VnodeBacking::UserspaceHandle { path, .. } => path,
        }
    }

    pub fn is_directory(&self) -> bool {
        self.inode.kind == VnodeKind::Directory
    }

    pub fn cext_handle_id(&self) -> Option<u64> {
        match &self.backing {
            VnodeBacking::LegacyPath(_) | VnodeBacking::UserspaceHandle { .. } => None,
            VnodeBacking::CextHandle { handle, .. } => Some(*handle),
        }
    }

    pub fn userspace_handle_ids(&self) -> Option<(u64, u64)> {
        match &self.backing {
            VnodeBacking::UserspaceHandle {
                node_id, open_id, ..
            } => Some((*node_id, *open_id)),
            VnodeBacking::LegacyPath(_) | VnodeBacking::CextHandle { .. } => None,
        }
    }
}

impl Drop for Vnode {
    fn drop(&mut self) {
        if let VnodeBacking::CextHandle { handle, .. } = &self.backing {
            let _ = crate::cext::fs::close_handle(*handle);
        }
        if let VnodeBacking::UserspaceHandle { open_id, .. } = &self.backing {
            if *open_id != 0 {
                let _ = userspace::close(self.inode.mount_id.0, *open_id);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    pub id: MountId,
    pub filesystem_id: FilesystemId,
    pub target: String,
    pub source: String,
}

pub struct ResolvedMount {
    pub mount_id: MountId,
    pub filesystem_id: FilesystemId,
    pub path: String,
}

static NEXT_MOUNT_ID: AtomicU64 = AtomicU64::new(2);
static MOUNTS: SpinLock<Vec<Mount>> = SpinLock::new(Vec::new());

/// Installs the compatibility root mount used during the userspace-filesystem
/// transition. Additional filesystems can be mounted at more specific paths.
pub fn init() {
    let mut mounts = MOUNTS.lock();
    if mounts.is_empty() {
        mounts.push(Mount {
            id: MountId(1),
            filesystem_id: FilesystemId(1),
            target: "/".to_string(),
            source: "/".to_string(),
        });
    }
}

pub fn mount(target: &str, filesystem_id: FilesystemId) -> Result<MountId, ()> {
    mount_from(target, filesystem_id, "/")
}

pub fn mount_from(target: &str, filesystem_id: FilesystemId, source: &str) -> Result<MountId, ()> {
    let target = normalize_mount_path(target);
    let source = normalize_mount_path(source);
    let mut mounts = MOUNTS.lock();
    if mounts.iter().any(|mount| mount.target == target) {
        return Err(());
    }
    let id = MountId(NEXT_MOUNT_ID.fetch_add(1, Ordering::Relaxed));
    mounts.push(Mount {
        id,
        filesystem_id,
        target,
        source,
    });
    Ok(id)
}

pub fn unmount(id: MountId) -> bool {
    if id == MountId(1) {
        return false;
    }
    let mut mounts = MOUNTS.lock();
    let Some(index) = mounts.iter().position(|mount| mount.id == id) else {
        return false;
    };
    mounts.remove(index);
    true
}

/// Resolves using the longest component-boundary mount-point match.
pub fn resolve(path: &str) -> Option<ResolvedMount> {
    let mounts = MOUNTS.lock();
    let mount = mounts
        .iter()
        .filter(|mount| mount_matches(&mount.target, path))
        .max_by_key(|mount| mount.target.len())?;
    let relative = path.strip_prefix(&mount.target).unwrap_or(path);
    let relative = relative.trim_start_matches('/');
    let mut source_path = mount.source.trim_end_matches('/').to_string();
    if !relative.is_empty() {
        source_path.push('/');
        source_path.push_str(relative);
    }
    Some(ResolvedMount {
        mount_id: mount.id,
        filesystem_id: mount.filesystem_id,
        path: if source_path.is_empty() {
            "/".to_string()
        } else {
            source_path
        },
    })
}

fn mount_matches(target: &str, path: &str) -> bool {
    target == "/"
        || path == target
        || path
            .strip_prefix(target)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn normalize_mount_path(path: &str) -> String {
    let mut normalized = String::new();
    for component in path.split('/').filter(|component| !component.is_empty()) {
        normalized.push('/');
        normalized.push_str(component);
    }
    if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

fn legacy_inode_id(path: &str) -> u64 {
    // FNV-1a is only a transitional identity for the path-based backend. The
    // userspace filesystem protocol supplies the real filesystem inode ID.
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
