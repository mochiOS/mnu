use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use super::DriverManifest;

#[derive(Clone, Debug)]
pub struct PackageManifest {
    pub package_id: String,
    pub package_name: String,
    pub package_root: String,
    pub about_path: String,
    pub entry_path: String,
    pub driver: DriverManifest,
}

static PACKAGES: Mutex<Option<BTreeMap<String, PackageManifest>>> = Mutex::new(None);

fn with_packages_mut<R>(f: impl FnOnce(&mut BTreeMap<String, PackageManifest>) -> R) -> R {
    let mut guard = PACKAGES.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn with_packages<R>(f: impl FnOnce(&BTreeMap<String, PackageManifest>) -> R) -> R {
    let mut guard = PACKAGES.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub fn register_package(manifest: PackageManifest) -> bool {
    with_packages_mut(|packages| {
        if packages.contains_key(&manifest.package_id) {
            return false;
        }

        packages.insert(manifest.package_id.clone(), manifest);
        true
    })
}

pub fn package_manifest(id: &str) -> Option<PackageManifest> {
    with_packages(|packages| packages.get(id).cloned())
}

pub fn package_manifests() -> Vec<PackageManifest> {
    with_packages(|packages| packages.values().cloned().collect())
}
