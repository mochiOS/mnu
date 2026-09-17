//! Canonical metadata for named mochiOS capabilities.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityClassification {
    UserGrantable,
    Privileged,
    SystemOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityMetadata {
    pub name: &'static str,
    pub classification: CapabilityClassification,
    pub delegable: bool,
    pub user_grantable: bool,
}

macro_rules! user {
    ($name:literal) => {
        CapabilityMetadata { name: $name, classification: CapabilityClassification::UserGrantable, delegable: true, user_grantable: true }
    };
}
macro_rules! privileged {
    ($name:literal) => {
        CapabilityMetadata { name: $name, classification: CapabilityClassification::Privileged, delegable: false, user_grantable: false }
    };
}
macro_rules! system {
    ($name:literal) => {
        CapabilityMetadata { name: $name, classification: CapabilityClassification::SystemOnly, delegable: false, user_grantable: false }
    };
}

pub const CAPABILITIES: &[CapabilityMetadata] = &[
    user!("fs.read.user.documents"), user!("fs.write.user.documents"),
    user!("fs.read.user.downloads"), user!("fs.write.user.downloads"),
    user!("fs.read.user.desktop"), user!("fs.write.user.desktop"),
    user!("fs.read.user.pictures"), user!("fs.write.user.pictures"),
    user!("fs.read.user.music"), user!("fs.write.user.music"),
    user!("fs.read.user.videos"), user!("fs.write.user.videos"),
    user!("fs.read.user"), user!("fs.write.user"),
    user!("fs.read.tmp"), user!("fs.write.tmp"),
    user!("fs.read.removable"), user!("fs.write.removable"),
    privileged!("fs.read.all"), privileged!("fs.write.all"),
    user!("net.connect"), user!("net.listen"), privileged!("net.raw"),
    user!("net.tls.connect"), user!("net.http.request"),
    system!("ipc.client"), system!("ipc.server"),
    system!("process.spawn"), system!("process.inspect"), system!("process.kill"),
    user!("window.create"), user!("window.overlay"),
    system!("window.secure-overlay"), privileged!("window.decorate"),
    privileged!("window.capture"), user!("display.read"),
    privileged!("display.capture"), user!("input.keyboard"),
    privileged!("input.keyboard.global"), user!("input.pointer"),
    privileged!("input.pointer.global"), privileged!("input.gamepad"),
    user!("audio.playback"), user!("audio.record"),
    user!("clipboard.read"), user!("clipboard.write"),
    user!("notification.send"), privileged!("camera.access"),
    privileged!("microphone.access"), privileged!("location.access"),
    privileged!("bluetooth.access"), privileged!("usb.access"),
    privileged!("serial.access"), privileged!("power.shutdown"),
    privileged!("power.reboot"), privileged!("power.suspend"),
    user!("system.time.read"), system!("system.random.read"),
    privileged!("system.time.set"), user!("system.info.read"),
    user!("system.logs.read"), privileged!("package.install"),
    privileged!("package.remove"), privileged!("package.update"),
    privileged!("service.register"), privileged!("service.control"),
    privileged!("vm.create"), privileged!("vm.control"),
    system!("dma.allocate"), system!("memory.phys.map"),
    system!("memory.phys.translate"), system!("kernel.module.load"),
    system!("kernel.debug"), privileged!("device.gpu"),
    privileged!("device.audio"), privileged!("device.input"),
    privileged!("device.storage"), privileged!("device.net"),
    user!("account.self.read"), user!("account.self.modify"),
    privileged!("account.authenticate"), privileged!("account.other.read"),
    privileged!("account.other.modify"), user!("settings.read"),
    privileged!("settings.write"), system!("capabilities.manage"),
    system!("unsandboxed"), system!("developer.debug"),
    system!("developer.profile"), system!("developer.tracing"),
    system!("signature.db.read"), system!("signature.db.write"),
];

pub fn metadata(name: &str) -> Option<&'static CapabilityMetadata> {
    CAPABILITIES.iter().find(|metadata| metadata.name == name)
}
