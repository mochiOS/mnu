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
