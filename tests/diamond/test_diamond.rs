use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// `choose_version` consults the dependency cache before it asks the repository, and the
// cache is only populated by `get_dependencies` -- so the cached half of that function
// runs only when the solver revisits a package it has already fetched dependencies for.
// Every fixture the other targets build is a tree: each package is reached once, the
// cache lookup misses, and the cached branch never runs. Here the same leaf is asked
// for two ways with ranges that disagree: the manifest says `>=1`, which resolves to the
// top tag, and `left` says `^1`, which excludes it. The first assignment is therefore
// wrong, the solver has to back off it, and the second `choose_version` for the leaf is
// the one that finds the cached entry -- the revisit a tree cannot produce.
#[test]
fn test_diamond() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/diamond")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    // The leaf carries three tags so the two ranges have a real intersection (1.5.0)
    // and a real disagreement (2.0.0 satisfies `>=1` and is excluded by `^1`).
    let leaf =
        common::build_fixture_repository(&fixtures, "leaf", &["1.0.0", "1.5.0", "2.0.0"], "")
            .unwrap();
    let leaf_url: String = leaf.display().to_string();

    let left_yaml: String =
        format!("dependencies:\n  - version: \"^1\"\n    url: file://{leaf_url}\n",);
    let left = common::build_fixture_repository(&fixtures, "left", &["2.0.0"], &left_yaml).unwrap();
    let left_url: String = left.display().to_string();

    let manifest_text: String = format!(
        "dependencies:\n  - version: \">=1\"\n    url: file://{leaf_url}\n  - version: \"^2\"\n    url: file://{left_url}\n",
    );
    println!("fixture manifest: {manifest_text}");
    fs::write("dependencies.yaml", manifest_text).unwrap();

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    // The leaf is a package in its own right -- unlike a submodule, which belongs to
    // its parent's tree -- so both names are pinned.
    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    let pinned: usize = lockfile.packages.len();
    anyhow::ensure!(
        pinned == 2,
        "the lockfile pins {pinned} packages, expected 2",
    );

    // The intersection, not either parent's maximum: `>=1` alone would take 2.0.0 and
    // `^1` alone would take 1.5.0, so 1.5.0 is only reachable by backing off the first
    // guess -- which is the revisit the cached half of `choose_version` needs.
    let leaf_version: String = lockfile
        .packages
        .get(&"leaf".to_string())
        .unwrap()
        .version
        .to_string();
    anyhow::ensure!(
        leaf_version == "1.5.0",
        "the shared leaf resolved to {leaf_version}, expected 1.5.0",
    );
    anyhow::ensure!(
        lockfile
            .packages
            .get(&"left".to_string())
            .unwrap()
            .version
            .to_string()
            == "2.0.0",
        "left resolved away from 2.0.0",
    );
    common::verify_lockfile_versions(&lockfile)?;

    // The shared leaf is one checkout, not one per parent: it is a package the
    // manifest graph reaches twice, and a package gets exactly one entry in
    // `.gitvenv` regardless of how many parents name it.
    let leaf_checkout = Path::new(".gitvenv").join("leaf");
    anyhow::ensure!(
        leaf_checkout.join("VERSION").exists(),
        "the shared leaf has no checkout: {}",
        leaf_checkout.display().to_string(),
    );

    // A warm run must not re-resolve the graph into a different selection.
    common::check(
        common::gipm_command(&cache).arg("update"),
        "gipm update (warm)",
    )?;
    let warm = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    let warm_leaf: String = warm
        .packages
        .get(&"leaf".to_string())
        .unwrap()
        .version
        .to_string();
    anyhow::ensure!(
        warm_leaf == leaf_version,
        "the warm run moved the shared leaf to {warm_leaf}",
    );
    let warm_pinned: usize = warm.packages.len();
    anyhow::ensure!(
        warm_pinned == 2,
        "the warm run pinned {warm_pinned} packages, expected 2",
    );
    common::verify_lockfile_versions(&warm)?;

    set_current_dir(cwd).unwrap();
    common::remove_tree(&fixtures).unwrap();
    common::remove_tree(&cache).unwrap();
    fs::remove_file("dependencies.yaml")?;

    Ok(())
}
