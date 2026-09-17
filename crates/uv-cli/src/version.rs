//! Code for representing uv's release version number.
// See also <https://github.com/astral-sh/ruff/blob/8118d29419055b779719cc96cdf3dacb29ac47c9/crates/ruff/src/version.rs>
use std::fmt;

use serde::Serialize;

use uv_normalize::PackageName;
use uv_pep508::uv_pep440::Version;

/// Name of the fork's distribution, reported in place of `uv` so that a
/// fork build can be told apart from an official uv release.
const FORK_PACKAGE_NAME: &str = "uv-pkcs11";

/// Information about the git repository where uv was built from.
#[derive(Serialize)]
pub(crate) struct CommitInfo {
    short_commit_hash: String,
    commit_hash: String,
    commit_date: String,
    last_tag: Option<String>,
    commits_since_last_tag: u32,
}

/// Version information for uv itself (e.g., in `uv self version`).
#[derive(Serialize)]
pub struct SelfVersionInfo {
    /// Name of the package (always [`FORK_PACKAGE_NAME`]).
    package_name: String,
    /// Version, such as "0.5.1".
    version: String,
    /// Version of the uv-pkcs11 distribution, such as "0.5.1.1": the upstream
    /// `version` with a fourth component for fork re-releases.
    fork_version: String,
    /// Information about the git commit we may have been built from.
    ///
    /// `None` if not built from a git repo or if retrieval failed.
    commit_info: Option<CommitInfo>,
    /// The target triple for which uv was built (e.g., `x86_64-unknown-linux-gnu`).
    target_triple: String,
}

/// Version information for a project (`uv version`).
#[derive(Serialize)]
pub struct ProjectVersionInfo {
    /// Name of the package.
    pub package_name: Option<String>,
    /// Version, such as "0.5.1".
    version: String,
    /// Information about the git commit uv was built from.
    ///
    /// Always `null` for project versions, kept for backwards compatibility.
    // TODO(zanieb): Remove this field in a breaking release.
    commit_info: Option<CommitInfo>,
}

impl ProjectVersionInfo {
    pub fn new(package_name: Option<&PackageName>, version: &Version) -> Self {
        Self {
            package_name: package_name.map(ToString::to_string),
            version: version.to_string(),
            commit_info: None,
        }
    }
}

impl SelfVersionInfo {
    /// Returns just the version string (e.g., "0.5.1"), without commit info or target triple.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl fmt::Display for SelfVersionInfo {
    /// Formatted version information:
    /// "<version>[+<commits>] ([<commit> <date> ]<target>) [<fork package name> <fork version>]"
    ///
    /// This is intended for consumption by `clap` to provide `uv --version`,
    /// and intentionally omits the `uv` command name; the trailing fork marker
    /// identifies the build as [`FORK_PACKAGE_NAME`] rather than official uv,
    /// and names the exact fork release, while `<version>` stays the upstream
    /// version that `required-version` is checked against.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)?;
        if let Some(ci) = &self.commit_info {
            if ci.commits_since_last_tag > 0 {
                write!(f, "+{}", ci.commits_since_last_tag)?;
            }
            write!(
                f,
                " ({} {} {})",
                ci.short_commit_hash, ci.commit_date, self.target_triple
            )?;
        } else {
            write!(f, " ({})", self.target_triple)?;
        }
        write!(f, " [{} {}]", self.package_name, self.fork_version)?;
        Ok(())
    }
}

impl fmt::Display for ProjectVersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.version)
    }
}

impl fmt::Display for CommitInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.commits_since_last_tag > 0 {
            write!(f, "+{}", self.commits_since_last_tag)?;
        }
        write!(f, " ({} {})", self.short_commit_hash, self.commit_date)?;
        Ok(())
    }
}

impl From<SelfVersionInfo> for clap::builder::Str {
    fn from(val: SelfVersionInfo) -> Self {
        val.to_string().into()
    }
}

/// Returns information about uv's version.
pub fn uv_self_version() -> SelfVersionInfo {
    // Environment variables are only read at compile-time
    macro_rules! option_env_str {
        ($name:expr) => {
            option_env!($name).map(|s| s.to_string())
        };
    }

    // This version is pulled from Cargo.toml and set by Cargo
    let version = uv_version::version().to_string();

    // Commit info is pulled from git and set by `build.rs`
    let commit_info = option_env_str!("UV_COMMIT_HASH").map(|commit_hash| CommitInfo {
        short_commit_hash: option_env_str!("UV_COMMIT_SHORT_HASH").unwrap(),
        commit_hash,
        commit_date: option_env_str!("UV_COMMIT_DATE").unwrap(),
        last_tag: option_env_str!("UV_LAST_TAG"),
        commits_since_last_tag: option_env_str!("UV_LAST_TAG_DISTANCE")
            .as_deref()
            .map_or(0, |value| value.parse::<u32>().unwrap_or(0)),
    });

    // Set by `uv-cli/build.rs`
    let target_triple = env!("RUST_HOST_TARGET").to_string();

    // Set by `uv-cli/build.rs` from `pyproject.toml`; the crate version when
    // building without the distribution's `pyproject.toml`.
    let fork_version = option_env_str!("UV_PKCS11_VERSION").unwrap_or_else(|| version.clone());

    SelfVersionInfo {
        package_name: FORK_PACKAGE_NAME.to_owned(),
        version,
        fork_version,
        commit_info,
        target_triple,
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_json_snapshot, assert_snapshot};

    use super::{CommitInfo, FORK_PACKAGE_NAME, SelfVersionInfo};

    #[test]
    fn version_formatting() {
        let version = SelfVersionInfo {
            package_name: FORK_PACKAGE_NAME.to_string(),
            version: "0.0.0".to_string(),
            fork_version: "0.0.0.1".to_string(),
            commit_info: None,
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        };
        assert_snapshot!(version, @"0.0.0 (x86_64-unknown-linux-gnu) [uv-pkcs11 0.0.0.1]");
    }

    #[test]
    fn version_formatting_with_commit_info() {
        let version = SelfVersionInfo {
            package_name: FORK_PACKAGE_NAME.to_string(),
            version: "0.0.0".to_string(),
            fork_version: "0.0.0.1".to_string(),
            commit_info: Some(CommitInfo {
                short_commit_hash: "53b0f5d92".to_string(),
                commit_hash: "53b0f5d924110e5b26fbf09f6fd3a03d67b475b7".to_string(),
                last_tag: Some("v0.0.1".to_string()),
                commit_date: "2023-10-19".to_string(),
                commits_since_last_tag: 0,
            }),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        };
        assert_snapshot!(version, @"0.0.0 (53b0f5d92 2023-10-19 x86_64-unknown-linux-gnu) [uv-pkcs11 0.0.0.1]");
    }

    #[test]
    fn version_formatting_with_commits_since_last_tag() {
        let version = SelfVersionInfo {
            package_name: FORK_PACKAGE_NAME.to_string(),
            version: "0.0.0".to_string(),
            fork_version: "0.0.0.1".to_string(),
            commit_info: Some(CommitInfo {
                short_commit_hash: "53b0f5d92".to_string(),
                commit_hash: "53b0f5d924110e5b26fbf09f6fd3a03d67b475b7".to_string(),
                last_tag: Some("v0.0.1".to_string()),
                commit_date: "2023-10-19".to_string(),
                commits_since_last_tag: 24,
            }),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        };
        assert_snapshot!(version, @"0.0.0+24 (53b0f5d92 2023-10-19 x86_64-unknown-linux-gnu) [uv-pkcs11 0.0.0.1]");
    }

    #[test]
    fn version_serializable() {
        let version = SelfVersionInfo {
            package_name: FORK_PACKAGE_NAME.to_string(),
            version: "0.0.0".to_string(),
            fork_version: "0.0.0.1".to_string(),
            commit_info: Some(CommitInfo {
                short_commit_hash: "53b0f5d92".to_string(),
                commit_hash: "53b0f5d924110e5b26fbf09f6fd3a03d67b475b7".to_string(),
                last_tag: Some("v0.0.1".to_string()),
                commit_date: "2023-10-19".to_string(),
                commits_since_last_tag: 0,
            }),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
        };
        assert_json_snapshot!(version, @r#"
        {
          "package_name": "uv-pkcs11",
          "version": "0.0.0",
          "fork_version": "0.0.0.1",
          "commit_info": {
            "short_commit_hash": "53b0f5d92",
            "commit_hash": "53b0f5d924110e5b26fbf09f6fd3a03d67b475b7",
            "commit_date": "2023-10-19",
            "last_tag": "v0.0.1",
            "commits_since_last_tag": 0
          },
          "target_triple": "x86_64-unknown-linux-gnu"
        }
        "#);
    }
}
