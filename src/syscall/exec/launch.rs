use mnu_abi::process_image::StartupImage;

/// Kernel-internal launch mechanism. A userspace label or executable identity
/// cannot select bootstrap authority or change scheduling/return semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ImageLaunch<'a> {
    Bootstrap(Option<StartupImage<'a>>),
    Created(StartupImage<'a>),
}

impl<'a> ImageLaunch<'a> {
    pub(super) fn is_bootstrap(self) -> bool {
        matches!(self, Self::Bootstrap(_))
    }

    pub(super) fn startup(self) -> Option<StartupImage<'a>> {
        match self {
            Self::Bootstrap(startup) => startup,
            Self::Created(startup) => Some(startup),
        }
    }
}

/// Complete authority for an image, never an optional fallback to ambient state.
pub(super) struct LaunchSecurity {
    pub capabilities: crate::capability::CapabilitySet,
    pub authorities: crate::capability::KernelAuthoritySet,
    pub privilege: crate::task::PrivilegeLevel,
    pub application_identity: Option<crate::task::process::ApplicationIdentity>,
}

/// Image construction consumes one explicit description, rather than ordered
/// optional arguments whose combinations have to be remembered by callers.
pub(super) struct PreparedLaunch<'a> {
    pub data: &'a [u8],
    pub process_name: &'a str,
    pub exec_path: &'a str,
    pub security: LaunchSecurity,
    pub inherited_handles: &'a [super::InheritedHandleGrant],
    pub inherited_values: &'a [super::InheritedValueSpec],
    pub launch: ImageLaunch<'a>,
}
