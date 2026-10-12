use crate::git::GitPackage;
use crate::git::PackageUrl;
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
            PackageUrl::GitUrl(self.url.clone()),
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

#[cfg(test)]
#[test]
fn test_parse_yaml_content() -> anyhow::Result<()> {
    let content: String =
        "dependencies:\n  - version: \"^1\"\n    url: file://./fixtures/pkg.git\n    prefix: v\n    replacement:\n      - [\"_\", \".\"]\n".to_string();

    let specs: Vec<DependencySpecification> = parse_dependencies_yaml_content(&content)?;
    let count: usize = specs.len();
    anyhow::ensure!(count == 1, "expected one specification, got {count}",);

    let spec: DependencySpecification = specs[0].clone();
    anyhow::ensure!(
        spec.version == "^1"
            && spec.url == "file://./fixtures/pkg.git"
            && spec.prefix == Some("v".to_string())
            && spec.replacement == Some(vec![["_".to_string(), ".".to_string()]]),
        "the specification lost its prefix or replacement: {spec}",
    );

    // Both optional fields default when the manifest omits them.
    let bare: String =
        "dependencies:\n  - version: \">=0.1\"\n    url: file://./fixtures/leaf.git\n".to_string();
    let bare_specs: Vec<DependencySpecification> = parse_dependencies_yaml_content(&bare)?;
    anyhow::ensure!(
        bare_specs.len() == 1 && bare_specs[0].prefix == None && bare_specs[0].replacement == None,
        "omitted fields must default to None",
    );

    // A truncated document is an authoring error, not an empty dependency set.
    let broken: Result<Vec<DependencySpecification>> =
        parse_dependencies_yaml_content("dependencies: [");
    anyhow::ensure!(broken.is_err(), "truncated yaml parsed as an empty set");

    Ok(())
}

#[cfg(test)]
#[test]
fn test_bounding_ranges() -> anyhow::Result<()> {
    let specs: Vec<DependencySpecification> = vec![
        DependencySpecification::new("^1".to_string(), "file://a.git".to_string(), None, None),
        DependencySpecification::new(">=0.1".to_string(), "file://b.git".to_string(), None, None),
    ];

    let pairs: Vec<(GitPackage, Ranges<Version>)> =
        dependency_spec_to_package_and_version_range(specs)?;
    let count: usize = pairs.len();
    anyhow::ensure!(
        count == 2,
        "expected two resolved specifications, got {count}",
    );

    let caret: Version = Version::new(1, 5, 0);
    let too_high: Version = Version::new(2, 0, 0);
    anyhow::ensure!(
        pairs[0].1.contains(&caret) && !pairs[0].1.contains(&too_high),
        "^1 must accept 1.5.0 and reject 2.0.0",
    );

    let lower: Version = Version::new(0, 1, 0);
    let too_low: Version = Version::new(0, 0, 9);
    anyhow::ensure!(
        pairs[1].1.contains(&lower) && !pairs[1].1.contains(&too_low),
        ">=0.1 must accept 0.1.0 and reject 0.0.9",
    );

    // A version string that is not a requirement fails the whole conversion,
    // carrying the specification it came from.
    let bad: Vec<DependencySpecification> = vec![DependencySpecification::new(
        "not_a_version".to_string(),
        "file://c.git".to_string(),
        None,
        None,
    )];
    let result: Result<Vec<(GitPackage, Ranges<Version>)>> =
        dependency_spec_to_package_and_version_range(bad);
    anyhow::ensure!(result.is_err(), "a non-requirement string must not resolve");

    Ok(())
}
