use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// Every failure mode below is hermetic: the unreachable url is a path that does
// not exist rather than a dead host, so the assertion cannot drift with the
// network. What each mode has to prove is the same pair of things -- gipm exits
// non-zero (the CLI reports the failure itself and calls `exit(1)`, it does not
// return the error to anyhow) and the cause chain reaches stderr intact.
#[test]
fn test_failure() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/failure")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let pkg = common::build_fixture_repository(&fixtures, "pkg", &["1.0.0", "1.5.0"], "")?;
    let pkg_url: String = pkg.display().to_string();

    // A manifest naming a repository that is not there. The provider turns the
    // clone failure into `Dependencies::Unavailable` -- a version that cannot be
    // chosen -- rather than aborting the solve, so the solver still has to fail.
    let missing: String = fixtures.join("nope").display().to_string();
    let manifest: String =
        format!("dependencies:\n  - version: \"^1\"\n    url: file://{missing}\n",);
    fs::write("dependencies.yaml", manifest)?;

    let stderr: String =
        common::expect_failure(common::gipm_command(&cache).arg("update"), "gipm update")?;
    anyhow::ensure!(
        stderr.contains("Unable to update dependency database"),
        "an unreachable url must be named as the dependency that failed: {stderr}",
    );
    anyhow::ensure!(
        stderr.contains("No version selection satisfies"),
        "an unreachable url must still end in a solver failure: {stderr}",
    );

    // A range nothing in the repository can satisfy. The package clones fine;
    // it is the solve that has to fail, which is the other half of
    // `choose_version` (it returns `None` rather than erroring).
    let manifest: String =
        format!("dependencies:\n  - version: \">=9.9.9\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    let stderr: String =
        common::expect_failure(common::gipm_command(&cache).arg("update"), "gipm update")?;
    anyhow::ensure!(
        stderr.contains("No version selection satisfies"),
        "an unsatisfiable range must report the solver failure: {stderr}",
    );

    // A `version` string that is not a range at all. This is the parse failure,
    // which happens before the solver runs.
    let manifest: String =
        format!("dependencies:\n  - version: \"not a range\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    let stderr: String =
        common::expect_failure(common::gipm_command(&cache).arg("update"), "gipm update")?;
    anyhow::ensure!(
        stderr.contains("Failed to parse version requirement"),
        "a bad version string must name the requirement that failed to parse: {stderr}",
    );

    // A manifest that does not match the schema.
    fs::write(
        "dependencies.yaml",
        "dependencies:\n  - versio oops\n".to_string(),
    )?;

    let stderr: String =
        common::expect_failure(common::gipm_command(&cache).arg("update"), "gipm update")?;
    anyhow::ensure!(
        stderr.contains("Failed to parse dependencies.yaml content"),
        "a malformed manifest must say which file it could not read: {stderr}",
    );

    // `sync` with no lockfile to replay -- none was written, because every run
    // above failed before the solver could produce a selection.
    let stderr: String =
        common::expect_failure(common::gipm_command(&cache).arg("sync"), "gipm sync")?;
    anyhow::ensure!(
        !stderr.is_empty(),
        "sync with no lockfile must report why it failed: {stderr}",
    );

    // A failure must not leave a half-written checkout behind that the next run
    // would then treat as dirty.
    anyhow::ensure!(
        !Path::new(".gitvenv").exists(),
        "a failed run left a checkout at .gitvenv behind",
    );

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
