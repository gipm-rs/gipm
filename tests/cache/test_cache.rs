use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// A cached database directory is not usable because it exists. An interrupted
// fetch leaves a directory that opens as a repository and still answers
// `references()`, but whose refs point at objects that were never downloaded --
// trusting that is what made later runs report "Object ... does not exist in the
// database" for a sha upstream still publishes. This target builds exactly that
// residue and shows the guard recovers instead of failing.
#[test]
fn test_cache() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/cache")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let manifest_text = common::build_fixture_scenario(&fixtures, "dependencies.yaml").unwrap();
    println!("fixture manifest: {manifest_text}");

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&lockfile)?;

    let databases: usize = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        databases == 4,
        "the scenario fetches four packages, cached {} databases",
        databases,
    );

    // Leave one database holding its refs but no objects: the residue described
    // above, which opens happily and answers `references()`.
    let corrupted: usize = common::corrupt_cached_database(&cache).unwrap();
    anyhow::ensure!(
        corrupted == 1,
        "corrupted {} databases, expected exactly one",
        corrupted,
    );

    // `update` has to notice the residue and re-clone rather than trust it. The
    // run must succeed and the checkout must still match the lockfile -- a
    // recovered database is indistinguishable from a healthy one downstream, so
    // the lockfile check is the assertion that it recovered rather than
    // half-worked.
    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update over a corrupted cache",
    )?;
    common::verify_lockfile_versions(&lockfile)?;

    // `sync` reaches the same guard through its own clone path, and the
    // residue is still there -- the run above recovered the database it needed,
    // but a package whose checkout is already in place is not re-fetched.
    let corrupted: usize = common::corrupt_cached_database(&cache).unwrap();
    anyhow::ensure!(
        corrupted == 1,
        "corrupted {} databases, expected exactly one",
        corrupted,
    );

    common::check(
        common::gipm_command(&cache).arg("sync"),
        "gipm sync over a corrupted cache",
    )?;
    common::verify_lockfile_versions(&lockfile)?;

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
