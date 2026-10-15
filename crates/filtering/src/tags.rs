//! Explicit, bounded client tags compiled off the query executor.
use crate::{ClientContext, CompileError};
/// Supported AdGuard Home tag vocabulary, in stable bit order.
pub const CLIENT_TAGS: [&str; 21] = [
    "device_audio",
    "device_camera",
    "device_gameconsole",
    "device_laptop",
    "device_nas",
    "device_pc",
    "device_phone",
    "device_printer",
    "device_securityalarm",
    "device_tablet",
    "device_tv",
    "device_other",
    "os_android",
    "os_ios",
    "os_linux",
    "os_macos",
    "os_windows",
    "os_other",
    "user_admin",
    "user_regular",
    "user_child",
];
/// Immutable tag mask. Construction validates the supported vocabulary offline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientTags(u32);
impl ClientTags {
    /// Compile explicitly assigned tags; duplicates and unknown values fail.
    pub fn compile<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Self, CompileError> {
        let mut bits = 0;
        for name in names {
            let bit = tag_bit(name)?;
            if bits & bit != 0 {
                return Err(CompileError::Domain("duplicate filtering tag".into()));
            }
            bits |= bit;
        }
        Ok(Self(bits))
    }
    /// Assigned names in the stable source vocabulary order.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        CLIENT_TAGS
            .into_iter()
            .enumerate()
            .filter(move |(index, _)| self.0 & (1 << index) != 0)
            .map(|(_, name)| name)
    }
    pub(super) fn bits(self) -> u32 {
        self.0
    }
}
/// Original identity plus explicitly configured tags from its pinned binding.
#[derive(Clone, Copy, Debug)]
pub struct FilterContext<'a> {
    /// Actual source address and binding name.
    pub client: ClientContext<'a>,
    /// Explicit filtering tags; inventory annotations are never used.
    pub tags: ClientTags,
}
impl<'a> ClientContext<'a> {
    /// Attach precompiled filtering tags, without changing legacy identity APIs.
    pub fn with_tags(self, tags: ClientTags) -> FilterContext<'a> {
        FilterContext { client: self, tags }
    }
}
impl<'a> From<ClientContext<'a>> for FilterContext<'a> {
    fn from(client: ClientContext<'a>) -> Self {
        client.with_tags(ClientTags::default())
    }
}
/// Per-rule tag restrictions. Exclusions win; inclusions match any listed tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize)]
pub struct TagSelector {
    include: Box<[&'static str]>,
    exclude: Box<[&'static str]>,
    #[serde(skip)]
    include_mask: u32,
    #[serde(skip)]
    exclude_mask: u32,
}
impl TagSelector {
    /// Sorted included tags; empty means all clients not excluded.
    pub fn include(&self) -> &[&'static str] {
        &self.include
    }
    /// Sorted excluded tags.
    pub fn exclude(&self) -> &[&'static str] {
        &self.exclude
    }
    /// Match a validated precompiled client mask.
    pub fn matches(&self, tags: ClientTags) -> bool {
        tags.0 & self.exclude_mask == 0
            && (self.include_mask == 0 || tags.0 & self.include_mask != 0)
    }
    pub(super) fn mask(&self) -> u32 {
        self.include_mask | self.exclude_mask
    }
    pub(super) fn count(&self) -> usize {
        self.include.len() + self.exclude.len()
    }
    pub(super) fn payload_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.count() * std::mem::size_of::<&str>()
    }
    pub(super) fn parse(text: &str) -> Result<Self, CompileError> {
        if text.is_empty() || text.split('|').count() > 64 {
            return Err(CompileError::Domain(
                "invalid or oversized ctag modifier".into(),
            ));
        }
        let (mut include, mut exclude, mut include_mask, mut exclude_mask) =
            (Vec::new(), Vec::new(), 0, 0);
        for value in text.split('|') {
            let (excluded, name) = value
                .strip_prefix('~')
                .map_or((false, value), |name| (true, name));
            let index = CLIENT_TAGS
                .iter()
                .position(|tag| *tag == name)
                .ok_or_else(|| CompileError::Domain("unsupported filtering tag".into()))?;
            if excluded {
                exclude.push(CLIENT_TAGS[index]);
                exclude_mask |= 1 << index;
            } else {
                include.push(CLIENT_TAGS[index]);
                include_mask |= 1 << index;
            }
        }
        include.sort_unstable();
        include.dedup();
        exclude.sort_unstable();
        exclude.dedup();
        Ok(Self {
            include: include.into_boxed_slice(),
            exclude: exclude.into_boxed_slice(),
            include_mask,
            exclude_mask,
        })
    }
}
fn tag_bit(name: &str) -> Result<u32, CompileError> {
    CLIENT_TAGS
        .iter()
        .position(|tag| *tag == name)
        .map(|index| 1 << index)
        .ok_or_else(|| CompileError::Domain("unsupported filtering tag".into()))
}
