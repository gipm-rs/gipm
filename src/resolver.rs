use crate::dependency::{
    dependency_spec_to_package_and_version_range, parse_dependencies_yaml_file,
};
use crate::git::GitPackage;
use crate::git::PackageUrl;
use anyhow::Result;
use pubgrub::{
    Dependencies, DependencyConstraints, DependencyProvider, Map, PackageResolutionStatistics,
    Ranges,
};
use rayon::prelude::*;
use semver::Version;
use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::Infallible;

// Version set type
type VS = Ranges<Version>;

struct DependencyCache {
    dependencies: Map<GitPackage, BTreeMap<Version, DependencyConstraints<GitPackage, VS>>>,
    dbs_updated: HashMap<PackageUrl, bool>,
}

impl DependencyCache {
    /// Initialize cached dependencies.
    pub fn new() -> Self {
        Self {
            dependencies: Map::default(),
            dbs_updated: HashMap::default(),
        }
    }

    pub fn add_dependencies<I: IntoIterator<Item = (GitPackage, VS)>>(
        &mut self,
        package: GitPackage,
        version: impl Into<Version>,
        dependencies: I,
    ) {
        let package_deps = dependencies.into_iter().collect();
        *self
            .dependencies
            .entry(package)
            .or_default()
            .entry(version.into())
            .or_default() = package_deps;
    }

    /// Extract dependencies of a given package from the cache.
    pub fn get_dependencies(
        &mut self,
        package: &GitPackage,
        version: &Version,
    ) -> Result<Dependencies<GitPackage, VS, String>, Infallible> {
        let dep_spec = match &package.url {
            PackageUrl::Root => Some(
                parse_dependencies_yaml_file("dependencies.yaml")
                    .expect("Failed to parse dependencies"),
            ),
            PackageUrl::GitUrl(_) => match package.fetch_dependencies_yaml(version) {
                Ok(p) => p,
                Err(e) => {
                    println!(
                        "Unable to get dependencies for {} version {version}. This version cannot be chosen:\n\t{e}",
                        package.name(),
                    );
                    return Ok(Dependencies::Unavailable(e.to_string()));
                }
            },
        };

        let mut constraints = DependencyConstraints::default();
        if let Some(dep_spec) = dep_spec {
            match dependency_spec_to_package_and_version_range(dep_spec) {
                Ok(deps_vec) => {
                    let mut deps_to_update = deps_vec
                        .iter()
                        .filter(|(dep, _)| {
                            !self.dbs_updated.get(&dep.url).copied().unwrap_or(false)
                        })
                        .cloned()
                        .collect::<Vec<_>>();

                    // Update databases in parallel
                    deps_to_update.par_iter_mut().for_each(|(dep, _)| {
                        dep.update_db().expect("Failed to update db");
                    });

                    // Update the map of updated dbs, so we avoid redundant updates
                    for (dep, _) in &deps_to_update {
                        self.dbs_updated.insert(dep.url.clone(), true);
                    }

                    // Constraints are handled post update
                    for (dep, vers) in &deps_vec {
                        constraints.insert(dep.clone(), vers.clone());
                    }
                }
                Err(e) => {
                    println!(
                        "Unable to resolve version range for package {} version {version}. This version cannot be chosen:\n\t{e}",
                        package.name(),
                    );
                    return Ok(Dependencies::Unavailable(e.to_string()));
                }
            }
        }
        self.add_dependencies(package.clone(), version.clone(), constraints.clone());
        Ok(Dependencies::Available(constraints.clone()))
    }
}

pub struct GitDependencyProvider {
    cache: RefCell<DependencyCache>,
}

impl Default for GitDependencyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl GitDependencyProvider {
    pub fn new() -> Self {
        Self {
            cache: RefCell::new(DependencyCache::new()),
        }
    }

    pub fn add_dependencies<I: IntoIterator<Item = (GitPackage, VS)>>(
        &mut self,
        package: GitPackage,
        version: impl Into<Version>,
        dependencies: I,
    ) {
        self.cache
            .borrow_mut()
            .add_dependencies(package, version, dependencies);
    }
}
impl DependencyProvider for GitDependencyProvider {
    type P = GitPackage;
    type V = Version;
    type VS = VS;
    type M = String;
    type Err = Infallible;

    #[inline]
    fn choose_version(
        &self,
        package: &Self::P,
        range: &Self::VS,
    ) -> Result<Option<Self::V>, Self::Err> {
        if package.url == PackageUrl::Root {
            // The root package is a special case; it has no versions to choose from
            return Ok(Some(Version::new(0, 0, 0)));
        }
        println!(
            "Choosing version for package: {}, range: {range}",
            package.name()
        );

        let version = match self
            .cache
            .borrow()
            .dependencies
            .get(package)
            .and_then(|versions| versions.keys().rev().find(|v| range.contains(v)).cloned())
        {
            Some(version) => Some(version),
            None => package
                .get_available_versions()
                .unwrap_or_else(|e| panic!("Should be able to get versions for package {}: {e}", package.name()))
                .keys()
                .filter(|v| range.contains(v))
                .max()
                .cloned(),
        };

        match &version {
            Some(v) => println!("Package: {}, version: {v}", package.name()),
            None => println!("No available versions for package {}", package.name()),
        }

        Ok(version)
    }

    type Priority = (u32, Reverse<usize>);

    #[inline]
    fn prioritize(
        &self,
        package: &Self::P,
        range: &Self::VS,
        package_statistics: &PackageResolutionStatistics,
    ) -> Self::Priority {
        let version_count = self
            .cache
            .borrow()
            .dependencies
            .get(package)
            .map(|versions| versions.keys().filter(|v| range.contains(v)).count())
            .unwrap_or(0);
        if version_count == 0 {
            return (u32::MAX, Reverse(0));
        }
        (package_statistics.conflict_count(), Reverse(version_count))
    }

    fn get_dependencies(
        &self,
        package: &Self::P,
        version: &Self::V,
    ) -> Result<Dependencies<Self::P, Self::VS, Self::M>, Self::Err> {
        let result = self
            .cache
            .borrow_mut()
            .get_dependencies(package, version)
            .unwrap();
        Ok(result)
    }
}
