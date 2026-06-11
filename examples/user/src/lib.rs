#![no_std]

extern crate alloc;

use alloc::string::String;

/// kernel 側 policy に渡す launch contract の userland 側テスト用表現
///
/// ここでは manifest のパースは扱わず、固定のデータ形だけを検証する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestRole {
    CoreService,
    Service,
    Application,
    Driver,
    Tool,
    Unknown,
}

/// install source の userland 側テスト用表現
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallSource {
    Initfs,
    Rootfs,
    BuiltIn,
    PackageStore,
    RemovableMedia,
    Network,
    Debug,
    Unknown,
}

/// kernel の `LaunchSpec` に対応する最小 contract
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchContract {
    pub package_id: String,
    pub publisher_id: String,
    pub signature_trusted: bool,
    pub manifest_role: ManifestRole,
    pub file_digest: [u8; 32],
    pub install_source: InstallSource,
}

impl LaunchContract {
    pub fn new(
        package_id: &str,
        publisher_id: &str,
        signature_trusted: bool,
        manifest_role: ManifestRole,
        file_digest: [u8; 32],
        install_source: InstallSource,
    ) -> Self {
        Self {
            package_id: String::from(package_id),
            publisher_id: String::from(publisher_id),
            signature_trusted,
            manifest_role,
            file_digest,
            install_source,
        }
    }

    /// 形式上の最小要件だけを見る
    pub fn is_well_formed(&self) -> bool {
        !self.package_id.is_empty() && !self.publisher_id.is_empty()
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launch_contract_keeps_all_required_fields() {
        let digest = [0xAB; 32];
        let contract = LaunchContract::new(
            "core.service",
            "mnu",
            true,
            ManifestRole::CoreService,
            digest,
            InstallSource::Initfs,
        );

        assert_eq!(contract.package_id, "core.service");
        assert_eq!(contract.publisher_id, "mnu");
        assert!(contract.signature_trusted);
        assert_eq!(contract.manifest_role, ManifestRole::CoreService);
        assert_eq!(contract.file_digest, digest);
        assert_eq!(contract.install_source, InstallSource::Initfs);
        assert!(contract.is_well_formed());
    }

    #[test]
    fn launch_contract_rejects_empty_identity_fields() {
        let contract = LaunchContract::new(
            "",
            "",
            false,
            ManifestRole::Unknown,
            [0; 32],
            InstallSource::Unknown,
        );

        assert!(!contract.is_well_formed());
    }
}
