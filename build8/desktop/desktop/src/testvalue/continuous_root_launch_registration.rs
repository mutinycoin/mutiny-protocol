//! Source-only prequalification placeholder. Root forms the actual finite body
//! with RootLaunchPolicy::FormTrustedChildAnchorSource from its original held
//! producer, reviews/adopts that source, then builds the child. No environment,
//! public file or CLI can install/replace the trusted issuer in this process.
pub(super) fn selected()->super::Result<super::RootLaunchAnchor>{
 Err("Actual Root-selected launcher anchor has not been formed/adopted; no provider effects".into())
}
