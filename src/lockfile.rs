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
