//! Version policy layered on top of the updater plugin's signature check.

use semver::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatePolicyError {
    InvalidCurrentVersion,
    InvalidCandidateVersion,
}

/// Accept only a valid candidate whose SemVer precedence is strictly greater.
pub fn strictly_newer(current: &str, candidate: &str) -> Result<bool, UpdatePolicyError> {
    let current = Version::parse(current).map_err(|_| UpdatePolicyError::InvalidCurrentVersion)?;
    let candidate =
        Version::parse(candidate).map_err(|_| UpdatePolicyError::InvalidCandidateVersion)?;
    Ok(candidate > current)
}

#[cfg(test)]
mod tests {
    use super::{strictly_newer, UpdatePolicyError};

    #[test]
    fn accepts_strictly_newer_semver_only() {
        assert_eq!(strictly_newer("1.2.3", "1.2.4"), Ok(true));
        assert_eq!(strictly_newer("1.2.3-rc.1", "1.2.3"), Ok(true));
        assert_eq!(strictly_newer("1.2.3", "1.2.3"), Ok(false));
        assert_eq!(strictly_newer("1.2.4", "1.2.3"), Ok(false));
        assert_eq!(strictly_newer("1.2.3", "1.2.3-rc.1"), Ok(false));
    }

    #[test]
    fn malformed_versions_are_typed_errors() {
        assert_eq!(
            strictly_newer("v1.2.3", "1.2.4"),
            Err(UpdatePolicyError::InvalidCurrentVersion)
        );
        assert_eq!(
            strictly_newer("1.2.3", "latest"),
            Err(UpdatePolicyError::InvalidCandidateVersion)
        );
    }
}
