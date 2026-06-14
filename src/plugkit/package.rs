use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

use super::{DeviceBus, DriverManifest, MatchRule};

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

#[derive(Default)]
struct AboutDraft {
    package_id: Option<String>,
    package_name: Option<String>,
    version: Option<String>,
    description: Option<String>,
    developer: Option<String>,
    entry: Option<String>,
    api_version: Option<u32>,
    driver_class: Option<String>,
    matches: Vec<MatchRule>,
    capabilities: Vec<String>,
    provides: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Root,
    Driver,
    PlugKit,
    Capabilities,
    Provides,
    Match,
}

#[derive(Default)]
struct MatchDraft {
    bus: Option<DeviceBus>,
    vendor_id: Option<u32>,
    device_id: Option<u32>,
}

fn trim_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escape = false;
    for (idx, ch) in line.char_indices() {
        match ch {
            '"' if !escape => in_string = !in_string,
            '#' if !in_string => return line[..idx].trim_end(),
            '\\' if !escape => escape = true,
            _ => escape = false,
        }
    }
    line.trim_end()
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim(), value.trim()))
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    if !value.starts_with('"') || !value.ends_with('"') || value.len() < 2 {
        return None;
    }
    let mut out = String::new();
    let mut chars = value[1..value.len() - 1].chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let escaped = chars.next()?;
        match escaped {
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            other => out.push(other),
        }
    }
    Some(out)
}

fn parse_string_or_number(value: &str) -> Option<String> {
    if value.starts_with('"') {
        return unquote(value);
    }
    Some(value.trim().to_string())
}

fn parse_u32_like(value: &str) -> Option<u32> {
    let value = value.trim();
    let value = if value.starts_with('"') {
        unquote(value)?.trim().to_string()
    } else {
        value.to_string()
    };
    if let Some(hex) = value.strip_prefix("0x") {
        return u32::from_str_radix(hex, 16).ok();
    }
    if let Some(hex) = value.strip_prefix("0X") {
        return u32::from_str_radix(hex, 16).ok();
    }
    value.parse::<u32>().ok()
}

fn parse_device_bus(value: &str) -> Option<DeviceBus> {
    match value.trim().trim_matches('"') {
        "platform" => Some(DeviceBus::Platform),
        "pci" => Some(DeviceBus::Pci),
        "usb" => Some(DeviceBus::Usb),
        "virtio" => Some(DeviceBus::Virtio),
        "other" => Some(DeviceBus::Other),
        _ => None,
    }
}

fn parse_array(value: &str) -> Option<Vec<String>> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return None;
    }
    let mut out = Vec::new();
    let inner = value[1..value.len() - 1].trim();
    if inner.is_empty() {
        return Some(out);
    }
    for raw in inner.split(',') {
        let item = raw.trim();
        if item.is_empty() {
            continue;
        }
        out.push(unquote(item).unwrap_or_else(|| item.trim_matches('"').to_string()));
    }
    Some(out)
}

fn finalize_match(draft: &mut AboutDraft, current: &mut MatchDraft) {
    if current.bus.is_some() || current.vendor_id.is_some() || current.device_id.is_some() {
        draft.matches.push(MatchRule {
            bus: current.bus,
            class: None,
            vendor_id: current.vendor_id,
            device_id: current.device_id,
        });
    }
    *current = MatchDraft::default();
}

fn finalize_manifest(
    draft: AboutDraft,
    package_root: &str,
    about_path: &str,
) -> Option<PackageManifest> {
    let package_id = draft.package_id?;
    let package_name = draft.package_name?;
    let version = draft.version?;
    let entry = draft.entry?;
    let api_version = draft.api_version.unwrap_or(1);

    let driver = DriverManifest {
        id: package_id.clone(),
        name: package_name.clone(),
        version,
        description: draft.description,
        developer: draft.developer,
        api_version,
        driver_class: draft.driver_class,
        matches: draft.matches,
        capabilities: draft.capabilities,
        provides: draft.provides,
    };

    Some(PackageManifest {
        package_id,
        package_name,
        package_root: package_root.to_string(),
        about_path: about_path.to_string(),
        entry_path: alloc::format!("{}/{}", package_root.trim_end_matches('/'), entry),
        driver,
    })
}

fn parse_about_toml(text: &str, package_root: &str, about_path: &str) -> Option<PackageManifest> {
    let mut draft = AboutDraft::default();
    let mut section = Section::Root;
    let mut current_match = MatchDraft::default();

    for raw_line in text.lines() {
        let line = trim_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line == "[driver]" {
            finalize_match(&mut draft, &mut current_match);
            section = Section::Driver;
            continue;
        }
        if line == "[plugkit]" {
            finalize_match(&mut draft, &mut current_match);
            section = Section::PlugKit;
            continue;
        }
        if line == "[capabilities]" {
            finalize_match(&mut draft, &mut current_match);
            section = Section::Capabilities;
            continue;
        }
        if line == "[provides]" {
            finalize_match(&mut draft, &mut current_match);
            section = Section::Provides;
            continue;
        }
        if line == "[[match]]" {
            finalize_match(&mut draft, &mut current_match);
            section = Section::Match;
            continue;
        }

        let Some((key, value)) = split_key_value(line) else {
            continue;
        };

        match section {
            Section::Driver => match key {
                "id" => draft.package_id = parse_string_or_number(value),
                "name" => draft.package_name = parse_string_or_number(value),
                "version" => draft.version = parse_string_or_number(value),
                "description" => draft.description = unquote(value).or_else(|| Some(value.to_string())),
                "developer" => draft.developer = unquote(value).or_else(|| Some(value.to_string())),
                "entry" => draft.entry = parse_string_or_number(value),
                _ => {}
            },
            Section::PlugKit => match key {
                "api" => draft.api_version = parse_string_or_number(value)?.parse::<u32>().ok(),
                "driver_class" => draft.driver_class = parse_string_or_number(value),
                _ => {}
            },
            Section::Capabilities => match key {
                "requires" => draft.capabilities = parse_array(value)?,
                _ => {}
            },
            Section::Provides => match key {
                "interfaces" => draft.provides = parse_array(value)?,
                _ => {}
            },
            Section::Match => match key {
                "bus" => current_match.bus = parse_device_bus(value),
                "vendor_id" => current_match.vendor_id = parse_u32_like(value),
                "device_id" => current_match.device_id = parse_u32_like(value),
                _ => {}
            },
            Section::Root => {}
        }
    }

    finalize_match(&mut draft, &mut current_match);
    finalize_manifest(draft, package_root, about_path)
}

pub fn register_package(manifest: PackageManifest) -> bool {
    with_packages_mut(|packages| {
        packages.insert(manifest.package_id.clone(), manifest);
    });
    true
}

pub fn package_manifest(id: &str) -> Option<PackageManifest> {
    with_packages(|packages| packages.get(id).cloned())
}

pub fn package_manifests() -> Vec<PackageManifest> {
    with_packages(|packages| packages.values().cloned().collect())
}

pub fn discover_packages(root: &str) -> usize {
    let Some(entries) = crate::init::fs::readdir_path(root) else {
        return 0;
    };

    let mut loaded = 0usize;
    for entry in entries {
        let package_root = alloc::format!("{}/{}", root.trim_end_matches('/'), entry);
        if !crate::init::fs::is_directory(&package_root) {
            continue;
        }
        let about_path = alloc::format!("{}/about.toml", package_root);
        let Some(bytes) = crate::init::fs::read(&about_path) else {
            continue;
        };
        let Ok(text) = core::str::from_utf8(&bytes) else {
            crate::warn!("plugkit: invalid UTF-8 in {}", about_path);
            continue;
        };
        let Some(manifest) = parse_about_toml(text, &package_root, &about_path) else {
            crate::warn!("plugkit: failed to parse {}", about_path);
            continue;
        };
        if register_package(manifest) {
            loaded += 1;
        }
    }
    loaded
}
