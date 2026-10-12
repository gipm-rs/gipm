use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// `sync` replays whatever `gipm.lock` says, and the lockfile is a generated file
// that users edit and that a half-written run can leave behind. One of its fields
// -- `commit` -- is parsed into a `gix::ObjectId`, so it is the one input that can
// arrive in a shape the code cannot use. The invariant this target pins is that a
// broken entry is *reported*: the run exits non-zero, names the package, and still
// prints the table for the packages that did sync.
#[test]
fn test_broken() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/broken")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let pkg = common::build_fixture_repository(&fixtures, "pkg", &["1.0.0", "1.5.0"], "")?;
    let leaf = common::build_fixture_repository(&fixtures, "leaf", &["0.1.0"], "")?;

    let pkg_url: String = pkg.display().to_string();
    let leaf_url: String = leaf.display().to_string();

    let manifest: String = format!(
        "dependencies:\n  - version: \"^1\"\n    url: file://{pkg_url}\n  - version: \"^0.1\"\n    url: file://{leaf_url}\n",
    );
    fs::write("dependencies.yaml", manifest)?;

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    let good_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&good_lock)?;

    // Corrupt one entry: the sha becomes text that is not an object id.
    let corrupted: usize =
        common::corrupt_lockfile_commit("gipm.lock", "not-a-valid-commit").unwrap();
    anyhow::ensure!(
        corrupted == 1,
        "corrupted {} lockfile entries, expected one",
        corrupted,
    );

    let (ok, stdout, stderr) = common::run_captured(&cache, &["sync"])?;

    anyhow::ensure!(
        !ok,
        "a lockfile naming a commit that is not an object id must fail: {stderr}",
    );
    anyhow::ensure!(
        stderr.contains("Invalid commit hash"),
        "the bad commit field must be named as the cause: {stderr}",
    );

    // The table still has to be drawn: a partial failure shows what did resolve,
    // which is the same rule `install_dependencies` follows. The package that
    // failed is not a row -- it is reported on stderr, so the row set is the
    // packages that synced rather than the packages that were attempted.
    anyhow::ensure!(
        stdout.contains("+---"),
        "a failed sync printed no summary table: {stdout}",
    );
    anyhow::ensure!(
        stdout.contains("pkg"),
        "the package that did sync is missing from the table: {stdout}",
    );
    anyhow::ensure!(
        !stdout.contains("leaf"),
        "the package that failed to sync is missing from the log: {stderr}",
    );
    anyhow::ensure!(
        stderr.contains("leaf"),
        "the package that failed to sync is missing from the log: {stderr}",
    );

    // The checkout that was already in place is untouched: a failed sync must not
    // tear down what it could not fix.
    common::verify_lockfile_versions(&good_lock)?;

    // A second shape of broken entry: a well-formed object id that the database
    // does not hold -- the residue of a lockfile copied from a different fork. This
    // fails at the checkout rather than at the parse, and must be reported the same
    // way.
    let ghost: String = "0".repeat(40).to_string();
    let corrupted: usize = common::corrupt_lockfile_commit("gipm.lock", ghost.as_str())?;
    anyhow::ensure!(
        corrupted == 1,
        "corrupted {corrupted} lockfile entries, expected one",
    );

    let (ok, stdout, stderr) = common::run_captured(&cache, &["sync"])?;
    anyhow::ensure!(
        !ok,
        "a lockfile naming an object the database does not hold must fail: {stderr}",
    );
    anyhow::ensure!(
        stdout.contains("+---"),
        "a failed sync printed no summary table: {stdout}",
    );
    anyhow::ensure!(
        stderr.contains("leaf"),
        "the package that failed to sync is missing from the log: {stderr}",
    );
    anyhow::ensure!(
        stdout.contains("pkg"),
        "the package that did sync is missing from the table: {stdout}",
    );

    // Repair the lockfile by re-resolving, and show the same `sync` now succeeds --
    // the failure was the entry, not the repository.
    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (repair)",
    )?;
    common::check(
        common::gipm_command(&cache).arg("sync"),
        "gipm sync (replay)",
    )?;
    common::verify_lockfile_versions(&good_lock)?;

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
