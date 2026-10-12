use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

/// Read a small text file the fixtures write.
fn read_text(path: &Path) -> anyhow::Result<String> {
    let bytes: Vec<u8> = fs::read(path)?;

    Ok(String::from_utf8_lossy(&bytes).to_string())
}

/// Ask the checkout for its own HEAD, as git reads it back.
fn head_of(dir: &Path) -> anyhow::Result<String> {
    let output = common::fixture_git(dir)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .expect("Failed to run git rev-parse");

    anyhow::ensure!(output.status.success(), "git rev-parse failed in {:?}", dir);

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The tag refs a checkout carries, as `for-each-ref` prints them.
fn tags_of(dir: &Path) -> anyhow::Result<String> {
    let output = common::fixture_git(dir)
        .arg("for-each-ref")
        .arg("refs/tags")
        .output()
        .expect("Failed to run git for-each-ref");

    anyhow::ensure!(
        output.status.success(),
        "git for-each-ref failed in {:?}",
        dir
    );

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// `checkout_from_database` has two very different halves. When the checkout is
// already sitting at the tag the solver chose it bails out early -- that is what
// every warm run in the suite exercises. When it sits at a *different* tag it has
// to fetch that tag out of the database into the working repository, write the
// object over the worktree, and re-point HEAD: `fetch_tag_from_db`, the checkout,
// and the HEAD edit. Nothing in the suite had ever made the resolution change, so
// that whole half was unexercised.
#[test]
fn test_drift() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/drift")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let pkg = common::build_fixture_repository(&fixtures, "pkg", &["1.0.0", "1.5.0"], "")?;
    let pkg_url: String = pkg.display().to_string();

    // Pin the older tag first, so the checkout exists at a version the next
    // resolution will disagree with.
    let manifest: String =
        format!("dependencies:\n  - version: \"=1.0.0\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (old)",
    )?;

    let checkout = Path::new(".gitvenv").join("pkg");
    anyhow::ensure!(
        checkout.join("VERSION").exists(),
        "no checkout at {}",
        checkout.display().to_string(),
    );

    let old_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&old_lock)?;

    let content: String = read_text(&checkout.join("VERSION"))?;
    anyhow::ensure!(
        content.trim() == "1.0.0".to_string(),
        "the pinned checkout carries {}, expected 1.0.0",
        content.trim(),
    );

    // Widen the range: the same package now resolves to 1.5.0 while its checkout
    // still sits at 1.0.0. The tag is not in the working repository -- it lives in
    // the database -- so this run has to fetch it, rewrite the worktree and move
    // HEAD.
    let manifest: String =
        format!("dependencies:\n  - version: \"^1\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update (drift)",
    )?;

    let new_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&new_lock)?;

    // The worktree really moved: the file the fixture committed under that name
    // carries the new version, which only a checkout over the new object does.
    let content: String = read_text(&checkout.join("VERSION"))?;
    anyhow::ensure!(
        content.trim() == "1.5.0".to_string(),
        "a re-resolved checkout still carries {}, expected 1.5.0",
        content.trim(),
    );

    // HEAD points at the new commit rather than at whatever the clone left behind.
    let pinned: String = new_lock
        .packages
        .get(&"pkg".to_string())
        .unwrap()
        .commit
        .clone();
    let head: String = head_of(&checkout)?;
    anyhow::ensure!(
        head == pinned.clone(),
        "HEAD sits at {}, the lockfile pins {}",
        head,
        pinned,
    );

    // And the tag that had to be fetched is now recorded in the working
    // repository -- the run fetched, it did not re-clone.
    let tags: String = tags_of(&checkout)?;
    anyhow::ensure!(
        tags.contains("1.5.0"),
        "the fetched tag is missing from the checkout: {tags}",
    );

    // Drift back down: the same machinery has to work in the other direction,
    // fetching an older tag into a repository that already holds the newer one.
    let manifest: String =
        format!("dependencies:\n  - version: \"=1.0.0\"\n    url: file://{pkg_url}\n",);
    fs::write("dependencies.yaml", manifest)?;

    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (drift back)",
    )?;

    let back_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    common::verify_lockfile_versions(&back_lock)?;

    let content: String = read_text(&checkout.join("VERSION"))?;
    anyhow::ensure!(
        content.trim() == "1.0.0".to_string(),
        "drifting back left the checkout at {}, expected 1.0.0",
        content.trim(),
    );

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
