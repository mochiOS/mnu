extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

pub use plugkit_sys::{
    DeviceBus, DeviceClass, DeviceId, DeviceName, DevicePath, DeviceProperty, PlugKitDevice,
    PlugKitError, PlugKitEvent, PlugKitResources, PlugKitResult, ProbeResult,
};

mod package;

pub use package::{package_manifest, package_manifests, register_package, PackageManifest};

#[derive(Clone, Debug)]
pub struct MatchRule {
    pub bus: Option<DeviceBus>,
    pub class: Option<DeviceClass>,
    pub vendor_id: Option<u32>,
    pub device_id: Option<u32>,
}

impl MatchRule {
    pub fn matches(&self, device: &PlugKitDevice) -> bool {
        if let Some(bus) = self.bus {
            if device.bus() != bus {
                return false;
            }
        }
        if let Some(class) = self.class {
            if device.class() != class {
                return false;
            }
        }
        if let Some(vendor_id) = self.vendor_id {
            if device.vendor_id() != Some(vendor_id) {
                return false;
            }
        }
        if let Some(device_id) = self.device_id {
            if device.device_id() != Some(device_id) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct DriverManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub developer: Option<String>,
    pub api_version: u32,
    pub driver_class: Option<String>,
    pub matches: Vec<MatchRule>,
    pub capabilities: Vec<String>,
    pub provides: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct DriverDescriptor {
    pub name: &'static str,
    pub type_name: &'static str,
    pub api_version: u32,
    pub probe: fn(&PlugKitDevice) -> ProbeResult,
    pub start: fn(PlugKitDevice, PlugKitResources) -> PlugKitResult<()>,
    pub stop: fn(PlugKitDevice) -> PlugKitResult<()>,
}

#[derive(Clone, Debug)]
pub struct RegisteredDriver {
    pub manifest: DriverManifest,
    pub descriptor: DriverDescriptor,
    pub loaded: bool,
}

static DRIVERS: Mutex<Option<BTreeMap<String, RegisteredDriver>>> = Mutex::new(None);
static DEVICE_ASSIGNMENTS: Mutex<Option<BTreeMap<u64, Option<String>>>> = Mutex::new(None);

fn with_drivers_mut<R>(f: impl FnOnce(&mut BTreeMap<String, RegisteredDriver>) -> R) -> R {
    let mut guard = DRIVERS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

fn with_assignments_mut<R>(f: impl FnOnce(&mut BTreeMap<u64, Option<String>>) -> R) -> R {
    let mut guard = DEVICE_ASSIGNMENTS.lock();
    let map = guard.get_or_insert_with(BTreeMap::new);
    f(map)
}

pub fn register_driver(manifest: DriverManifest, descriptor: DriverDescriptor) -> bool {
    with_drivers_mut(|drivers| {
        if drivers.contains_key(&manifest.id) {
            return false;
        }

        drivers.insert(
            manifest.id.clone(),
            RegisteredDriver {
                manifest,
                descriptor,
                loaded: true,
            },
        );
        true
    })
}

pub fn unregister_driver(id: &str) -> bool {
    with_drivers_mut(|drivers| drivers.remove(id).is_some())
}

pub fn driver_manifest(id: &str) -> Option<DriverManifest> {
    with_drivers_mut(|drivers| drivers.get(id).map(|d| d.manifest.clone()))
}

pub fn register_device(device: PlugKitDevice) {
    with_assignments_mut(|assignments| {
        assignments.entry(device.id().0).or_insert(None);
    });
}

pub fn choose_driver(device: &PlugKitDevice) -> Option<DriverDescriptor> {
    with_drivers_mut(|drivers| {
        let mut best: Option<(u32, DriverDescriptor)> = None;
        for driver in drivers.values() {
            let mut best_score = None;
            for rule in &driver.manifest.matches {
                if rule.matches(device) {
                    let mut score = 0u32;
                    if rule.bus.is_some() {
                        score += 1;
                    }
                    if rule.class.is_some() {
                        score += 1;
                    }
                    if rule.vendor_id.is_some() {
                        score += 2;
                    }
                    if rule.device_id.is_some() {
                        score += 2;
                    }
                    best_score = Some(best_score.map_or(score, |s: u32| s.max(score)));
                }
            }
            if let Some(score) = best_score {
                let replace = best.map_or(true, |(current, _)| score > current);
                if replace {
                    best = Some((score, driver.descriptor));
                }
            }
        }
        best.map(|(_, descriptor)| descriptor)
    })
}

pub fn bind_device_to_driver(device: &PlugKitDevice, driver_id: &str) -> PlugKitResult<()> {
    with_drivers_mut(|drivers| {
        let Some(driver) = drivers.get(driver_id) else {
            return Err(PlugKitError::NoDevice);
        };
        if driver
            .manifest
            .matches
            .iter()
            .any(|rule| rule.matches(device))
        {
            with_assignments_mut(|assignments| {
                assignments.insert(device.id().0, Some(driver_id.to_string()));
            });
            Ok(())
        } else {
            Err(PlugKitError::NotSupported)
        }
    })
}

pub fn assigned_driver(device: &PlugKitDevice) -> Option<String> {
    with_assignments_mut(|assignments| assignments.get(&device.id().0).cloned().flatten())
}

pub fn emit_event(event: PlugKitEvent) -> PlugKitResult<()> {
    plugkit_sys::emit_event(event)
}

// 　_(ﾟДﾟ)_
// Ｙ￣￣￣￣ヽ
// ∥ ∪ 　つ |
// ∥　(| |)　|
// ∥　　　　 |
// ∥　(| |)　|
// ∥　　　　 |
// ヽ＿＿＿＿ノ
// 　　∪∪
