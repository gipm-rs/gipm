use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// Every other fixture in the suite is created with `git init -b main`, so the
// default-branch code path -- the one that reads `HEAD` rather than a name --
// has only ever been exercised at its happy end. Here the repository's default
// branch is `trunk`, and nothing else about the package differs.
#[test]
fn test_branches() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/branches")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let trunk = common::build_fixture_repository_on(
        &fixtures,
        "trunk",
        "trunk",
        "",
        &["1.0.0", "1.5.0"],
        "",
    )?;
    let trunk_url: String = trunk.display().to_string();

    let manifest: String =
        format!("dependencies:\n  - version: \"^1\"\n    url: file://{trunk_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    // The checkout exists and carries the newest tag the range allows, which is
    // only reachable if the clone resolved the repository's own default branch.
    let checkout = Path::new(".gitvenv").join("trunk");
    anyhow::ensure!(
        checkout.join("VERSION").exists(),
        "no checkout for a non-main default branch: {}",
        checkout.display().to_string(),
    );

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    anyhow::ensure!(
        lockfile.packages.len() == 1,
        "the lockfile carries {} packages, expected just trunk",
        lockfile.packages.len(),
    );
    common::verify_lockfile_versions(&lockfile)?;

    // A second update is a no-op: the existing checkout is found by its default
    // branch, not by a hardcoded `main`.
    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update (warm)",
    )?;
    common::verify_lockfile_versions(&lockfile)?;

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
