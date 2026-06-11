#![no_std]

/// kernel 側 policy に渡す launch contract の userland 側表現
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

/// install source の userland 側表現
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
    pub package_id: &'static str,
    pub publisher_id: &'static str,
    pub signature_trusted: bool,
    pub manifest_role: ManifestRole,
    pub file_digest: [u8; 32],
    pub install_source: InstallSource,
}

impl LaunchContract {
    pub fn new(
        package_id: &'static str,
        publisher_id: &'static str,
        signature_trusted: bool,
        manifest_role: ManifestRole,
        file_digest: [u8; 32],
        install_source: InstallSource,
    ) -> Self {
        Self {
            package_id,
            publisher_id,
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

pub fn test_launch_contract_keeps_all_required_fields() -> bool {
    let digest = [0xAB; 32];
    let contract = LaunchContract::new(
        "core.service",
        "mnu",
        true,
        ManifestRole::CoreService,
        digest,
        InstallSource::Initfs,
    );

    contract.package_id == "core.service"
        && contract.publisher_id == "mnu"
        && contract.signature_trusted
        && contract.manifest_role == ManifestRole::CoreService
        && contract.file_digest == digest
        && contract.install_source == InstallSource::Initfs
        && contract.is_well_formed()
}

pub fn test_launch_contract_rejects_empty_identity_fields() -> bool {
    let contract = LaunchContract::new(
        "",
        "",
        false,
        ManifestRole::Unknown,
        [0; 32],
        InstallSource::Unknown,
    );

    !contract.is_well_formed()
}

pub fn run_self_test() -> bool {
    test_launch_contract_keeps_all_required_fields()
        && test_launch_contract_rejects_empty_identity_fields()
}
