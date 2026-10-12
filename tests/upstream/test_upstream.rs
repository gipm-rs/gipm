use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
#[path = "../common/mod.rs"]
mod common;

/// Upstream moving is the one scenario where a checkout that already exists cannot
/// find the object the solver picked: the new commit was created *after* the
/// checkout was cloned, so it is not in the checkout's object store -- the clone
/// hardlinked the database's objects as they were then, and a later fetch grows the
/// database, not the checkout. `checkout_object_at` therefore takes its fetch path
/// (`fetch_ref_from_db`) and re-points HEAD at the new commit.
#[test]
fn test_upstream() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/upstream")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    // One tag to begin with, so the first resolution has nowhere else to go.
    let pkg = common::build_fixture_repository(&fixtures, "pkg", &["1.0.0"], "")?;
    let pkg_url: String = pkg.display().to_string();

    let manifest: String =
        format!("dependencies:\n  - version: \"^1\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    let first = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&first)?;

    let checkout: PathBuf = Path::new(".gitvenv").join("pkg");
    let old_commit: String = first
        .packages
        .get(&"pkg".to_string())
        .unwrap()
        .commit
        .clone();

    // Upstream adds a commit and tags it. The tree is reused, so only the commit
    // object is new -- exactly what a checkout has to fetch.
    let new_commit: String = common::add_upstream_tag(&fixtures, "pkg", "1.5.0", "1.0.0")?;
    anyhow::ensure!(
        new_commit != old_commit.clone(),
        "the drift commit is the pinned one: {old_commit}",
    );

    // Prove the checkout genuinely lacks the new object before the run: the fetch
    // has to serve it, rather than the run finding it already present.
    let absent: anyhow::Result<String> =
        common::fixture_run(&checkout, &["cat-file", "-t", new_commit.as_str()]);
    anyhow::ensure!(
        absent.is_err(),
        "the checkout already held the upstream object: {new_commit}",
    );

    // The same range now resolves higher: the solver sees the new tag.
    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update (upstream moved)",
    )?;

    let second = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&second)?;

    let pinned: String = second
        .packages
        .get(&"pkg".to_string())
        .unwrap()
        .commit
        .clone();
    anyhow::ensure!(
        pinned == new_commit.clone(),
        "the lockfile pins {}, upstream tagged {}",
        pinned,
        new_commit,
    );

    // The checkout followed: HEAD names the new commit, which only a run that
    // fetched the missing object and re-pointed HEAD can leave behind.
    let head: String = common::fixture_run(&checkout, &["rev-parse", "HEAD"])?;
    anyhow::ensure!(
        head == pinned.clone(),
        "HEAD sits at {}, the lockfile pins {}",
        head,
        pinned,
    );

    // The tag had to be fetched too -- it did not exist when the checkout was made.
    let tags: String = common::fixture_run(&checkout, &["for-each-ref", "refs/tags"])?;
    anyhow::ensure!(
        tags.contains("1.5.0"),
        "the new tag is missing from the checkout: {tags}",
    );

    // The version the table reported is the new tag's.
    let version: String = second
        .packages
        .get(&"pkg".to_string())
        .unwrap()
        .version
        .to_string();
    anyhow::ensure!(
        version == "1.5.0".to_string(),
        "the lockfile carries version {}, expected 1.5.0",
        version,
    );

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
