// Clone a repository from any URL or Path to a given target directory

pub mod dependency;
pub mod git;
pub mod logging;
pub mod progress;
pub mod lockfile;
pub mod resolver;
use crate::git::GitPackage;
use crate::git::PackageUrl;
use anyhow::Context;
use lockfile::LockFile;
use log::{error, info};
use pubgrub::Ranges;
use pubgrub::resolve;
use rayon::prelude::*;
use resolver::GitDependencyProvider;
use semver::Version;
use std::collections::BTreeMap;
use std::fs;
use std::iter::zip;
use std::path::Path;
pub mod third_party;

pub fn sync_dependencies() -> anyhow::Result<()> {
    let lockfile = LockFile::from_file("gipm.lock")?;

    let packages: Vec<(String, lockfile::LockFilePackage)> =
        lockfile.packages.into_iter().collect();

    let handle = progress::start(packages.len());

    // Phase 1: Update all dependency databases in parallel
    let checkout_results: Vec<(&str, &str, GitPackage, anyhow::Result<()>)> = packages
        .par_iter()
        .map(
            |(name, package)| -> (&str, &str, GitPackage, anyhow::Result<()>) {
                let mut dep = GitPackage::new(
                    PackageUrl::GitUrl(package.source.clone()),
                    Some(name.clone()),
                    None,
                );
                let object = match package.commit.parse::<gix::ObjectId>() {
                    Ok(object) => object,
                    Err(e) => {
                        return (
                            name,
                            &package.commit,
                            dep,
                            Err(anyhow::anyhow!(format!(
                                "Invalid commit hash {}: {e:?}",
                                package.commit
                            ))),
                        );
                    }
                };
                let should_update = dep.does_id_exist_in_db(object).unwrap_or(false);
                if should_update && let Err(e) = dep.update_db() {
                    return (
                        name,
                        &package.commit,
                        dep,
                        Err(e.context(format!(
                            "Failed to update database for {} at commit {}",
                            name, package.commit
                        ))),
                    );
                };
                let label: String = format!(
                    "Updating checkout for {} at commit {}",
                    name, package.commit
                );
                info!("{}", label);

                let mut sub_progress = progress::child(name.to_string());

                match dep.checkout_or_clone_object_from_database(object, &mut sub_progress) {
                    Ok(_) => {
                        sub_progress.done("Complete");
                        progress::task_done(name.to_string());
                        (name, &package.commit, dep, Ok(()))
                    }
                    Err(e) => {
                        sub_progress.fail(format!("Failed: {}", logging::error_text(&e)));
                        progress::task_done(name.to_string());
                        (name, &package.commit, dep, Err(e))
                    }
                }
            },
        )
        .collect();

    handle.shutdown_and_wait();

    let mut rows: Vec<logging::SummaryRow> = vec![];
    let mut sync_success = true;

    for (name, version, dep, result) in checkout_results {
        match result {
            Ok(_) => {
                let status: String = if dep.is_dirty() {
                    logging::sym_dirty()
                } else {
                    logging::sym_ok()
                };

                rows.push(
                    logging::SummaryRow {
                        name: dep.name(),
                        version: "".to_string(),
                        tag: "".to_string(),
                        commit: version.to_string(),
                        status,
                    }
                );
            }
            Err(e) => {
                error!(
                    "Failed to check out {} at commit {}: {}",
                    name, version, logging::error_text(&e)
                );
                sync_success = false;
            }
        }
    }

    logging::render_summary("Synced dependencies".to_string(), rows);

    if sync_success {
        logging::result("All dependencies synced successfully".to_string());
        return Ok(());
    }

    Err(anyhow::anyhow!("Some dependencies failed to sync; see the log above for details."))
}

// Clean up any resolved dependencies. This only affects. gitvenv, not the gipm.lock file.
pub fn clean() -> anyhow::Result<()> {
    let git_deps_dir = Path::new(".gitvenv");
    if git_deps_dir.exists() {
        fs::remove_dir_all(git_deps_dir)?;
        logging::result("Deleted .gitvenv directory".to_string());
    }

    Ok(())
}

pub fn install_dependencies() -> anyhow::Result<()> {
    let handle = progress::start(0);

    // Initialize the dependency resolver
    let mut resolver = GitDependencyProvider::default();

    // Parse the entry dependencies with a dummy root node
    let root_dep = GitPackage::new(git::PackageUrl::Root, None, None);
    let dummy_root_version = Version::new(0, 0, 0);

    let dependency_specs = dependency::parse_dependencies_yaml_file("dependencies.yaml")?;

    let resolver_dependencies: Vec<(GitPackage, Ranges<Version>)> =
        dependency::dependency_spec_to_package_and_version_range(dependency_specs)
            .context("Failed to parse dependency specification for root project")?;

    resolver.add_dependencies(
        root_dep.clone(),
        dummy_root_version.clone(),
        resolver_dependencies,
    );

    // Resolve all dependencies
    let resolved_dependencies =
        resolve(&resolver, root_dep.clone(), dummy_root_version)
            .context(
                "No version selection satisfies the ranges in dependencies.yaml (the solver's reasoning is logged at -v)",
            )?;

    // pubgrub 0.4 hands back an opaque SelectedDependencies view (iter/get only),
    // so materialise it here: the root entry is dropped, and a Vec gives the
    // deterministic ordering the table, the lockfile and the tests all rely on.
    let resolved_dependencies: Vec<(GitPackage, Version)> = resolved_dependencies
        .iter()
        .filter(|(dep, _)| dep.url != git::PackageUrl::Root)
        .map(|(dep, version)| (dep.clone(), version.clone()))
        .collect();

    // Now that the graph is solved, the overall bar has an honest denominator.
    progress::set_expected(resolved_dependencies.len());

    // Checkout all resolved dependencies in parallel
    let result: Vec<anyhow::Result<()>> = resolved_dependencies
        .par_iter()
        .map(|(dep, version)| {
            info!("Checking out {} at version {}", dep.name(), version);
            let outcome: anyhow::Result<()> = dep.checkout_from_database(version);
            progress::task_done(dep.name());
            outcome
        })
        .collect();

    handle.shutdown_and_wait();

    let mut rows: Vec<logging::SummaryRow> = vec![];
    for (dep, version) in &resolved_dependencies {
        if let PackageUrl::GitUrl(_) = &dep.url {
            let status: String = if dep.is_dirty() {
                logging::sym_dirty()
            } else {
                logging::sym_ok()
            };

            let commit: String = dep.get_commit_hash_for_version(version).unwrap_or("".to_string());

            rows.push(
                logging::SummaryRow {
                    name: dep.name(),
                    version: version.to_string(),
                    tag: dep.get_tag_name(version).unwrap_or("invalid".to_string()),
                    commit: commit.clone(),
                    status,
                }
            );
        }
    }

    logging::render_summary("Resolved dependencies".to_string(), rows);

    // Report errors in the checkout *after* the table: a partial failure must still show
    // what did resolve, the same way `sync` does.
    for (result, (dep, ver)) in zip(&result, &resolved_dependencies) {
        if let Err(e) = result {
            return Err(
                anyhow::anyhow!("Error checking out - {} version {ver}: {e}", dep.name()),
            )
        }
    }

    let mut lockfile = LockFile::default();
    for (dep, version) in &resolved_dependencies {
        if dep.name() != root_dep.clone().name() {
            let repo = gix::open(dep.get_checkout_path()?)?;
            let commit = repo.head_commit().expect("HEAD should exist");
            let package_dependencies = dep.fetch_dependencies_yaml(version)?;
            let mut deps_map = BTreeMap::new();
            if let Some(deps) = package_dependencies {
                for dep_spec in deps {
                    let req = dep.parse_version_requirement(
                        &dep_spec.version,
                        &dep_spec.prefix,
                        &dep_spec.replacement,
                    )?;
                    deps_map.insert(
                        git::normalize_url(&PackageUrl::GitUrl(dep_spec.url.clone())),
                        req,
                    );
                }
            }
            let dependencies_to_add = if deps_map.is_empty() {
                None
            } else {
                Some(deps_map)
            };
            lockfile.add_package(
                dep.name(),
                version.clone(),
                dep.url.as_str().to_string(),
                commit.id.to_string(),
                dependencies_to_add,
            )?;
        }
    }

    lockfile.to_file("gipm.lock")?;

    logging::result("All dependencies resolved and checked out successfully".to_string());
    logging::result("Lockfile updated at gipm.lock".to_string());

    Ok(())
}
