use crate::dependency::{
    dependency_spec_to_package_and_version_range, parse_dependencies_yaml_file,
};
use crate::git::{GitPackage, PackageUrl, normalize_url};
use crate::logging;
use anyhow::Result;
use log::{trace, warn};
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
    dbs_updated: HashMap<String, bool>,
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
                    // A missing dependencies.yaml is a transport/authoring failure, not a
                    // resolution decision: it must be visible by default, otherwise the
                    // user only ever sees "There is no solution".
                    warn!(
                        "Unable to get dependencies for {} version {version}. This version cannot be chosen: {}",
                        package.name(),
                        logging::error_text(&e),
                    );
                    return Ok(Dependencies::Unavailable(e.to_string()));
                }
            },
        };

        let mut constraints = DependencyConstraints::default();
        if let Some(dep_spec) = dep_spec {
            match dependency_spec_to_package_and_version_range(dep_spec) {
                Ok(deps_vec) => {
                    // Filter for dependencies that haven't had their DB updated yet.
                    // Fix #3: Use normalized URL as the key to handle different url formats (ssh vs https)
                    // ensuring effective deduplication.
                    let mut deps_to_update: Vec<(GitPackage, VS)> = deps_vec
                        .iter()
                        .filter(|&(dep, _)| {
                            !self.dbs_updated.contains_key(&normalize_url(&dep.url))
                        })
                        .cloned()
                        .collect();

                    // Update databases in parallel.
                    // Note: the updated `GitPackage` values must be the ones handed back to
                    // pubgrub (see below), otherwise `all_versions` stays `None` for freshly
                    // cloned databases and `choose_version` panics in `get_available_versions`.
                    if !deps_to_update.is_empty() {
                        let update_results: Vec<anyhow::Result<()>> = deps_to_update
                            .par_iter_mut()
                            .map(|(dep, _)| dep.update_db())
                            .collect();

                        // Update the map of updated dbs using normalized keys for future lookups.
                        for ((dep, _), result) in deps_to_update.iter().zip(update_results.iter()) {
                            if let Err(e) = result {
                                let msg =
                                    format!("Failed to update database for {}: {e}", dep.name(),);
                                warn!(
                                    "Unable to update dependency database for {}: {}. This version cannot be chosen",
                                    dep.name(),
                                    logging::error_text(e),
                                );
                                return Ok(Dependencies::Unavailable(msg));
                            }
                            self.dbs_updated.insert(normalize_url(&dep.url), true);
                        }
                    }

                    // Index the database-updated packages by normalized url so the constraints
                    // we hand to pubgrub carry their resolved version information.
                    let updated_deps: HashMap<String, GitPackage> = deps_to_update
                        .iter()
                        .map(|(dep, _)| (normalize_url(&dep.url), dep.clone()))
                        .collect();

                    // Constraints are handled post update. pubgrub 0.4 dropped the
                    // mutating `insert` in favour of a FromIterator instance.
                    constraints = deps_vec
                        .iter()
                        .map(|(dep, vers)| {
                            let dep = updated_deps.get(&normalize_url(&dep.url)).unwrap_or(dep);
                            (dep.clone(), vers.clone())
                        })
                        .collect();
                }
                Err(e) => {
                    warn!(
                        "Unable to resolve version range for package {} version {version}. This version cannot be chosen: {}",
                        package.name(),
                        logging::error_text(&e),
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
        trace!(
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
                .unwrap_or_else(|e| {
                    panic!(
                        "Should be able to get versions for package {}: {e}",
                        package.name()
                    )
                })
                .keys()
                .filter(|v| range.contains(v))
                .max()
                .cloned(),
        };

        match &version {
            Some(v) => trace!("Package: {}, version: {v}", package.name()),
            None => trace!("No available versions for package {}", package.name()),
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

#[cfg(test)]
#[test]
fn test_cache_reports_an_unreachable_package() -> anyhow::Result<()> {
    let mut cache: DependencyCache = DependencyCache::new();

    // A package whose database was never cloned has no transitive manifest to read.
    // The provider must say so through pubgrub rather than inventing an empty set --
    // an empty set would resolve the package as a leaf and check it out.
    let pkg: GitPackage = GitPackage::new(
        PackageUrl::GitUrl("file://a-package-this-run-never-clones.git".to_string()),
        None,
        None,
    );
    let version: Version = Version::new(1, 0, 0);

    let result = cache.get_dependencies(&pkg, &version).unwrap();

    match result {
        Dependencies::Unavailable(message) => {
            let detail: String = message.clone();
            anyhow::ensure!(
                detail.contains("Database for dependency"),
                "the failure was not reported as an unavailable database: {detail}",
            );
        }
        Dependencies::Available(deps) => {
            let count: usize = deps.iter().count();
            anyhow::ensure!(
                count == 0,
                "an uncloned package reported {count} transitive dependencies",
            );
        }
    }

    Ok(())
}
