// Clone a repository from any URL or Path to a given target directory

pub mod dependency;
pub mod git;
pub mod lockfile;
pub mod resolver;
use crate::git::GitPackage;
use anyhow::Context;
use gix::progress::tree::Root;
use lockfile::LockFile;
use once_cell::sync::Lazy;
use pubgrub::Ranges;
use pubgrub::resolve;
use rayon::prelude::*;
use resolver::GitDependencyProvider;
use semver::Version;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::iter::zip;
use std::ops::RangeInclusive;
use std::path::Path;
pub mod third_party;

static PROGRESS: Lazy<std::sync::Arc<Root>> = Lazy::new(|| {
    let trace = false;
    gitoxide::shared::progress_tree(trace)
});

pub static VERBOSE: Lazy<bool> = Lazy::new(|| {
    // Load configuration from file or environment

    // This is kinda nasty and this shuold be replaced with a proper logging implementation.
    // Note this is tied to the verbose flag in the main method.
    env::args().any(|arg| arg == "-v" || arg == "--verbose")
});

pub fn sync_dependencies() -> anyhow::Result<()> {
    let lockfile = LockFile::from_file("gipm.lock")?;

    let packages: Vec<(String, lockfile::LockFilePackage)> =
        lockfile.packages.into_iter().collect();

    let progress_range: RangeInclusive<u8> = 1..=4;
    let handle = gitoxide::shared::setup_line_renderer_range(&PROGRESS, progress_range.clone());

    // Phase 1: Update all dependency databases in parallel
    let checkout_results: Vec<(&str, &str, anyhow::Result<()>)> = packages
        .par_iter()
        .map(|(name, package)| -> (&str, &str, anyhow::Result<()>) {
            let mut dep = GitPackage::new(package.source.clone(), Some(name.clone()), None);
            let object = match package.commit.parse::<gix::ObjectId>() {
                Ok(object) => object,
                Err(e) => {
                    return (
                        name,
                        &package.commit,
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
                    Err(e.context(format!(
                        "Failed to update database for {} at commit {}",
                        name, package.commit
                    ))),
                );
            };
            if *VERBOSE {
                println!(
                    "Updating checkout for {} at commit {}",
                    name, package.commit
                );
            }

            let mut sub_progress = PROGRESS.add_child(format!(
                "Updating checkout for {} at commit {}",
                name, package.commit
            ));

            match dep.checkout_or_clone_object_from_database(object, &mut sub_progress) {
                Ok(_) => {
                    sub_progress.done("Complete");
                    (name, &package.commit, Ok(()))
                }
                Err(e) => {
                    sub_progress.fail(format!("Failed:\n\t{e:?}"));
                    (name, &package.commit, Err(e))
                }
            }
        })
        .collect();

    handle.shutdown_and_wait();

    let mut sync_success = true;

    println!("Synced dependencies:");
    for (name, version, result) in checkout_results {
        match result {
            Ok(_) => {
                println!("  ✅ {name}: {version}");
            }
            Err(e) => {
                eprintln!("❌ Failed to check out {name} at version {version}: {e:?}");
                sync_success = false;
            }
        }
    }

    match sync_success {
        true => {
            println!("✅ All dependencies synced successfully!");
            Ok(())
        }
        false => Err(anyhow::anyhow!(
            "❌ Some dependencies failed to sync. See above log for details."
        )),
    }
}

// Clean up any resolved dependencies. This only affects. gitvenv, not the gipm.lock file.
pub fn clean() -> anyhow::Result<()> {
    let git_deps_dir = Path::new(".gitvenv");
    if git_deps_dir.exists() {
        fs::remove_dir_all(git_deps_dir)?;
        println!("Deleted .gitvenv directory");
    }

    Ok(())
}

pub fn install_dependencies() -> anyhow::Result<()> {
    // Initialize progress
    // Note turn false to true for tracing; maybe add to program args

    let progress_range: RangeInclusive<u8> = 1..=4;
    let handle = gitoxide::shared::setup_line_renderer_range(&PROGRESS, progress_range.clone());

    // Initialize the dependency resolver
    let mut resolver = GitDependencyProvider::default();

    // Parse the entry dependencies with a dummy root node
    let root_dep = GitPackage::new("GIPM_DUMMY_ROOT_URL".to_string(), None, None);
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
    let mut resolved_dependencies = resolve(&resolver, root_dep.clone(), dummy_root_version)?;

    // Remove the root dependency, as it is not an item to be checked out.
    resolved_dependencies.remove(&root_dep);

    // Checkout all resolved dependencies in parallel
    let result: Vec<anyhow::Result<()>> = resolved_dependencies
        .par_iter()
        .map(|(dep, version)| {
            if *VERBOSE {
                println!("Checking out {} at version {version}", dep.name());
            }
            dep.checkout_from_database(version)
        })
        .collect();

    handle.shutdown_and_wait();

    // Report errors in the checkout
    for (result, (dep, ver)) in zip(&result, &resolved_dependencies) {
        if let Err(e) = result {
            anyhow::bail!("Error checking out - {} version {ver}: {e}", dep.name())
        }
    }

    println!("Resolved dependencies:");
    for (dep, version) in &resolved_dependencies {
        if dep.name() != root_dep.clone().name() {
            println!(
                "  ✅ {}: {version} (tag {})",
                dep.name(),
                dep.get_tag_name(version).unwrap_or("invalid".to_string())
            );
        }
    }

    let mut lockfile = LockFile::default();
    for (dep, version) in &resolved_dependencies {
        if dep.name() != root_dep.clone().name() {
            let commit = dep.get_commit_hash_for_version(version)?;
            let package_dependencies = dep.fetch_dependencies_yaml(version)?;
            let mut deps_map = BTreeMap::new();
            if let Some(deps) = package_dependencies {
                for dep_spec in deps {
                    let req = dep.parse_version_requirement(
                        &dep_spec.version,
                        &dep.prefix,
                        &dep.replacements,
                    )?;
                    deps_map.insert(git::normalize_url(&dep.url), req);
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
                dep.url.clone(),
                commit,
                dependencies_to_add,
            )?;
        }
    }

    lockfile.to_file("gipm.lock")?;

    println!("✅ All dependencies resolved and checked out successfully!");
    println!("🔒 Lockfile updated at gipm.lock");

    Ok(())
}
