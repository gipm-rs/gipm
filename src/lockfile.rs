use anyhow::Context;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Serialize, Deserialize)]
pub struct LockFile {
    pub version: String,
    pub packages: BTreeMap<String, LockFilePackage>,
}

#[derive(Serialize, Deserialize)]
pub struct LockFilePackage {
    pub version: Version,
    pub source: String,
    pub commit: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dependencies: BTreeMap<String, VersionReq>,
}

impl Default for LockFile {
    fn default() -> Self {
        Self::new()
    }
}

impl LockFile {
    pub fn new() -> Self {
        Self {
            version: "1".to_string(),
            packages: BTreeMap::new(),
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let lockfile: LockFile =
            toml::from_str(&contents).context("Failed to parse lock file contents")?;
        Ok(lockfile)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let mut file = File::create(path)?;
        let contents = toml::to_string_pretty(&self)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }

    pub fn add_package(
        &mut self,
        name: String,
        version: Version,
        source: String,
        commit: String,
        dependencies: Option<BTreeMap<String, VersionReq>>,
    ) -> anyhow::Result<()> {
        self.packages.insert(
            name,
            LockFilePackage {
                version,
                source,
                commit,
                dependencies: dependencies.unwrap_or_default(),
            },
        );
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn test_lockfile_round_trip() -> anyhow::Result<()> {
    let mut file: LockFile = LockFile::default();
    anyhow::ensure!(
        file.version == "1" && file.packages.is_empty(),
        "a default lockfile is version 1 and empty",
    );

    let mut deps: BTreeMap<String, VersionReq> = BTreeMap::new();
    deps.insert("file://leaf.git".to_string(), VersionReq::parse(">=0.1")?);

    file.add_package(
        "pkg".to_string(),
        Version::new(1, 5, 0),
        "file://pkg.git".to_string(),
        "deadbeef".to_string(),
        Some(deps.clone()),
    )?;
    file.add_package(
        "bare".to_string(),
        Version::new(0, 1, 0),
        "file://bare.git".to_string(),
        "cafebabe".to_string(),
        None,
    )?;

    let count: usize = file.packages.len();
    anyhow::ensure!(count == 2, "expected two packages, got {count}",);

    // The file is TOML; a round trip has to preserve the typed fields, not just
    // the text.
    std::fs::create_dir_all("target/gipm-unit-scratch")?;
    let path: String = "target/gipm-unit-scratch/lockfile-round-trip.toml".to_string();
    file.to_file(&path)?;

    let back: LockFile = LockFile::from_file(&path)?;
    anyhow::ensure!(back.packages.len() == 2, "the round trip lost packages",);

    let pkg = back.packages.get(&"pkg".to_string()).unwrap();
    let pkg_version: String = pkg.version.to_string();
    let pkg_commit: String = pkg.commit.clone();
    let pkg_source: String = pkg.source.clone();
    let pkg_deps: usize = pkg.dependencies.len();
    anyhow::ensure!(
        pkg_commit == "deadbeef"
            && pkg_version == "1.5.0"
            && pkg_source == "file://pkg.git"
            && pkg_deps == 1,
        "the round trip changed the entry: {pkg_version} {pkg_source} {pkg_commit}",
    );

    // A package added without dependencies serializes to none, and reads back as
    // empty rather than missing.
    let bare = back.packages.get(&"bare".to_string()).unwrap();
    anyhow::ensure!(
        bare.dependencies.is_empty(),
        "an entry with no dependencies read back as some"
    );

    // A missing file and a malformed one are both errors -- an unreadable lockfile
    // must never read back as "no packages".
    let missing: anyhow::Result<LockFile> =
        LockFile::from_file("target/gipm-unit-scratch/definitely-absent.toml");
    anyhow::ensure!(missing.is_err(), "a missing lockfile parsed as empty");

    let bad_path: String = "target/gipm-unit-scratch/malformed.toml".to_string();
    std::fs::write(&bad_path, "this is [ not valid toml")?;
    let malformed: anyhow::Result<LockFile> = LockFile::from_file(&bad_path);
    anyhow::ensure!(malformed.is_err(), "malformed lockfile contents parsed");

    Ok(())
}
