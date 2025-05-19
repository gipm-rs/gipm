use crate::git::GitPackage;
use crate::third_party::semver_pubgrub::SemverPubgrub;
use anyhow::{Context, Result};
use pubgrub::Ranges;
use semver::Version;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::hash::Hash;
use std::io::Read;

#[derive(Clone, Debug, Eq, PartialEq, Hash, serde::Deserialize)]
pub struct DependencySpecification {
    // The version of the dependency
    // Expressed as a String version range
    pub version: String,

    // The remote URL of the dependency
    pub url: String,

    #[serde(default)]
    // The prefix for the version
    pub prefix: Option<String>,

    #[serde(default)]
    // The replacement for the version
    pub replacement: Option<Vec<[String; 2]>>,
}

#[derive(serde::Deserialize)]
struct DependenciesFile {
    dependencies: Vec<DependencySpecification>,
}

impl Display for DependencySpecification {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.url, self.version)
    }
}

impl DependencySpecification {
    pub fn new(
        version_string: String,
        url: String,
        prefix: Option<String>,
        replacement: Option<Vec<[String; 2]>>,
    ) -> Self {
        Self {
            version: version_string,
            url,
            prefix,
            replacement,
        }
    }

    pub fn to_package_and_version_range(&self) -> Result<(GitPackage, SemverPubgrub<Version>)> {
        let package = GitPackage::new(
            self.url.clone(),
            self.prefix.clone(),
            self.replacement.clone(),
        );

        let version_req = package
            .parse_version_requirement(&self.version, &self.prefix, &self.replacement)
            .context(format!(
                "Failed to parse version requirement for dependency specification {}, version {}",
                self.url, self.version
            ))?;

        let version_range: SemverPubgrub<Version> = (&version_req).into();

        Ok((package, version_range))
    }
}

/// Parse dependencies.yaml content from a string
pub fn parse_dependencies_yaml_content(content: &str) -> Result<Vec<DependencySpecification>> {
    let deps_file: DependenciesFile =
        serde_yaml::from_str(content).context("Failed to parse dependencies.yaml content")?;

    // Convert to Dependency structs
    let dependencies = deps_file.dependencies;
    Ok(dependencies)
}

pub fn parse_dependencies_yaml_file(path: &str) -> Result<Vec<DependencySpecification>> {
    // Read the file contents
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    parse_dependencies_yaml_content(&contents)
}

pub fn dependency_spec_to_package_and_version_range(
    dependencies: Vec<DependencySpecification>,
) -> Result<Vec<(GitPackage, Ranges<Version>)>> {
    dependencies
        .into_iter()
        .map(|d| {
            let (package, version_range) = d.to_package_and_version_range()?;
            let (start, end) = version_range
                .bounding_range()
                .ok_or_else(|| anyhow::anyhow!("No bounding range for version requirement"))?;
            Ok((
                package,
                Ranges::from_iter(vec![(start.cloned(), end.cloned())]),
            ))
        })
        .collect()
}

#[cfg(test)]
#[test]
fn test_dependency_specification() -> anyhow::Result<()> {
    let dep_spec = DependencySpecification::new(
        "1.0.0".to_string(),
        "github.com/user/repo.git".to_string(),
        Some("v".to_string()),
        Some(vec![["_".to_string(), "-".to_string()]]),
    );

    anyhow::ensure!(
        dep_spec.version == "1.0.0"
            && dep_spec.url == "github.com/user/repo.git"
            && dep_spec.prefix == Some("v".to_string())
            && dep_spec.replacement == Some(vec![["_".to_string(), "-".to_string()]]),
        "DependencySpecification did not initialize correctly"
    );

    // Coverage for Display formatter
    println!("{dep_spec}");

    Ok(())
}

#[cfg(test)]
#[test]
fn test_bad_version() -> anyhow::Result<()> {
    let dep_spec = DependencySpecification::new(
        "not_a_version".to_string(),
        "github.com/user/repo.git".to_string(),
        Some("v".to_string()),
        Some(vec![["_".to_string(), "-".to_string()]]),
    );

    let result = dep_spec.to_package_and_version_range();

    println!("Testing: {dep_spec}");

    anyhow::ensure!(
        result.is_err(),
        "Expect that version string did not parse correctly"
    );

    Ok(())
}
