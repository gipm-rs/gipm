use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// `sync` replays whatever `update` resolved, so the lockfile is generated here
// rather than committed with upstream shas baked in — a committed lockfile rots
// the moment an upstream release moves, which is what these tests used to do.
#[test]
fn test_sync() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/sync")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    common::build_fixture_scenario(&fixtures, "dependencies.yaml")?;

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();

    // Drop both the checkouts and the databases so `sync` has to rebuild the
    // databases and clone from them: with the checkouts still in place `sync`
    // finds the objects already present and never consults the cache at all,
    // which is the state where a half-written database used to be trusted.
    fs::remove_dir_all(Path::new(".gitvenv"))?;
    common::remove_tree(&cache)?;

    common::check(common::gipm_command(&cache).arg("sync"), "gipm sync")?;

    let rebuilt_databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        rebuilt_databases == lockfile.packages.len(),
        "sync against an empty cache left {} databases behind, expected one per package ({})",
        rebuilt_databases,
        lockfile.packages.len(),
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err(),
    );

    // Run again with the databases in place - only the checkouts are removed, so
    // the second sync has to reuse the cache rather than rebuild it.

    fs::remove_dir_all(Path::new(".gitvenv"))?;

    common::check(common::gipm_command(&cache).arg("sync"), "gipm sync")?;

    let warm_databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        warm_databases == rebuilt_databases,
        "Second sync changed the database cache: first {}, warm {}",
        rebuilt_databases,
        warm_databases,
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err(),
    );

    // Clean up
    fs::remove_dir_all(Path::new(".gitvenv")).unwrap();
    fs::remove_file("gipm.lock").unwrap();
    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
