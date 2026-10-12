use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The whole point of this target is the submodule path, which the other targets
// never reach: no fixture they build carries a submodule entry, so "it compiles"
// was the only evidence the gix submodule code had. Here `top` pins `mid`, which
// pins `leaf`, and every level is tagged *after* the entry is recorded so the tree
// gipm resolves really carries it.
#[test]
fn test_submodule() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/submodule")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    // The parent checkout is walked repeatedly, so it gets a name.
    let top = Path::new(".gitvenv").join("top");
    let nested = top.join("mid").join("leaf");

    let manifest_text =
        common::build_fixture_submodule_scenario(&fixtures, "dependencies.yaml").unwrap();
    println!("fixture manifest: {manifest_text}");

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    // A submodule is materialised below its parent -- `.gitvenv/top/mid/leaf` --
    // not at `.gitvenv/leaf`, which is what a path derived from the submodule's own
    // url would give. Two levels deep is the interesting case: the clone path ends
    // by walking the submodule table again, so the second level only exists if the
    // recursion actually happened.
    anyhow::ensure!(
        nested.join("VERSION").exists(),
        "nested submodule not fetched: {} is empty",
        nested.display().to_string(),
    );
    anyhow::ensure!(
        !Path::new(".gitvenv").join("leaf").exists(),
        "a submodule must not be checked out a second time at .gitvenv/leaf",
    );

    // Every submodule sits at the commit its parent pins, which is not necessarily
    // the child repository's HEAD.
    let pinned: usize = common::verify_submodule_pins(&top)?;
    anyhow::ensure!(
        pinned == 2,
        "expected two submodule levels, verified {}",
        pinned,
    );

    // The lockfile names only the package the manifest asked for: a submodule
    // belongs to its parent's tree, it is not a package of its own.
    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    anyhow::ensure!(
        lockfile.packages.len() == 1,
        "the lockfile carries {} packages, expected just top",
        lockfile.packages.len(),
    );
    let top_name: String = "top".to_string();
    anyhow::ensure!(
        lockfile.packages.get(&top_name).is_some(),
        "the lockfile names {:?}, expected top",
        lockfile.packages.keys().cloned().collect::<Vec<String>>(),
    );
    common::verify_lockfile_versions(&lockfile)?;

    // A second update must be a no-op: the checkout is already at the pinned tag,
    // and the submodule table is walked a second time over a tree that already
    // holds the child repository.
    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update (warm)",
    )?;
    anyhow::ensure!(
        nested.join("VERSION").exists(),
        "the warm run lost the nested submodule: {} is empty",
        nested.display().to_string(),
    );
    anyhow::ensure!(
        common::verify_submodule_pins(&top)? == 2,
        "the warm run moved a submodule off its pinned commit",
    );

    // Upstream moves a tag higher while the checkout is already sitting at the old
    // commit: the existing-checkout path has to re-checkout `top` at the new commit,
    // and the submodule table is walked over a tree that already holds the child
    // repositories at their old pins -- the half of `checkout_object_at` the clone
    // path never reaches, since here nothing is cloned and nothing is removed.
    let moved: String = common::add_upstream_tag(&fixtures, "top", "2.0.0", "1.0.0").unwrap();
    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (upstream moved)",
    )?;
    let moved_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    let moved_version: String = moved_lock
        .packages
        .get(&top_name)
        .unwrap()
        .version
        .to_string();
    anyhow::ensure!(
        moved_version == "2.0.0",
        "the moved upstream left top at {moved_version}, expected 2.0.0",
    );
    common::verify_lockfile_versions(&moved_lock)?;
    anyhow::ensure!(
        common::verify_submodule_pins(&top)? == 2,
        "the moved upstream left a submodule behind: {}",
        nested.display().to_string(),
    );

    // Tear the checkout down and replay it from the lockfile: `sync` reaches the
    // submodule through the clone path rather than the existing-checkout path, so
    // it is a different half of the code than the two runs above exercised.
    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;
    anyhow::ensure!(
        !Path::new(".gitvenv").exists(),
        "clean left {} behind",
        Path::new(".gitvenv").display().to_string(),
    );

    common::check(common::gipm_command(&cache).arg("sync"), "gipm sync")?;
    anyhow::ensure!(
        nested.join("VERSION").exists(),
        "sync did not fetch the nested submodule: {} is empty",
        nested.display().to_string(),
    );
    anyhow::ensure!(
        common::verify_submodule_pins(&top)? == 2,
        "sync left a submodule off its pinned commit",
    );

    // `update` on top of a synced tree must not re-fetch what is already there.
    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (after sync)",
    )?;
    anyhow::ensure!(
        common::verify_submodule_pins(&top)? == 2,
        "update after sync moved a submodule off its pinned commit",
    );

    // The databases: one per repository that had to be fetched, the submodules
    // included -- they are cached like any other package even though they never
    // appear in the lockfile.
    let databases: usize = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        databases == 3,
        "three repositories were fetched, cached {} databases",
        databases,
    );

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
