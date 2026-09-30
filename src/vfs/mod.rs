//! Filesystem object model shared by file descriptors and filesystem backends.

use alloc::string::String;
use alloc::sync::Arc;

/// Identifies a mounted filesystem instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MountId(pub u64);

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
}

/// A resolved filesystem object kept alive independently of a descriptor number.
pub struct Vnode {
    pub inode: Arc<Inode>,
    backing: VnodeBacking,
}

impl Vnode {
    pub fn legacy_path(path: String, kind: VnodeKind) -> Self {
        Self {
            inode: Arc::new(Inode {
                mount_id: MountId(0),
                inode_id: InodeId(legacy_inode_id(&path)),
                kind,
            }),
            backing: VnodeBacking::LegacyPath(path),
        }
    }

    pub fn path(&self) -> &str {
        match &self.backing {
            VnodeBacking::LegacyPath(path) => path,
        }
    }

    pub fn is_directory(&self) -> bool {
        self.inode.kind == VnodeKind::Directory
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
