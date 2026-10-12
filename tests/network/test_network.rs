use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The only target that reaches a live remote. It is opt-in: without GIPM_NETWORK=1
// it says so and passes, which is what CI and the coverage run do. When it is on
// it exercises the paths the file:// fixtures cannot: a real https handshake and
// server reply, a real repository-not-found reply, and a pty, which is the only
// way the progress renderer takes its drawing() branch.
#[test]
fn test_network() -> anyhow::Result<()> {
    let enabled: String = std::env::var("GIPM_NETWORK").unwrap_or("0".to_string());
    if enabled != "1" {
        println!("GIPM_NETWORK is not set to 1; skipping the real-upstream target");
        return Ok(());
    }

    set_current_dir(Path::new("tests/network")).unwrap();
    let cwd = current_dir().unwrap();
    let work = cwd.join("fixtures");
    let cache = cwd.join("cache");
    fs::create_dir_all(&work).unwrap();
    set_current_dir(&work).unwrap();

    // test-repo-1 is a purpose-built upstream: it carries semver tags (0.1.0 ...
    // 0.5.0) and declares its own dependencies, so the graph walk pulls test-repo-2
    // and eigen over the wire as well. Only test-repo-1's own version is asserted,
    // since the others are real upstreams that can move.
    let manifest: String =
        "dependencies:\n  - version: \">=0.3\"\n    url: https://github.com/gipm-rs/test-repo-1.git\n".to_string();
    fs::write("dependencies.yaml", manifest).unwrap();

    let (ok, stdout, stderr) = common::run_captured(&cache, &["update"]).unwrap();
    anyhow::ensure!(ok, "gipm update over https failed: {stderr}");
    anyhow::ensure!(
        stdout.contains("test-repo-1"),
        "the summary table never mentioned test-repo-1: {stdout}",
    );

    anyhow::ensure!(
        Path::new(".gitvenv").exists(),
        "no checkout directory after an https update",
    );

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    let pinned = lockfile.packages.get(&"test-repo-1".to_string()).unwrap();
    let pinned_version: String = pinned.version.to_string();
    anyhow::ensure!(
        pinned_version == "0.5.0",
        "test-repo-1 resolved to {pinned_version} rather than 0.5.0",
    );

    let databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        databases >= 1,
        "no database was cached for an https dependency: {databases}",
    );

    // A second update reuses the databases it just downloaded, which is the
    // reference-existence path a file:// fixture cannot distinguish (its clones
    // share objects with the source).
    let (warm, _, warm_stderr) = common::run_captured(&cache, &["update"]).unwrap();
    anyhow::ensure!(warm, "warm gipm update over https failed: {warm_stderr}");

    // The pty run is the only way to reach the render loop: over a pipe the
    // renderer declines to draw at all, so every bar below stays uncovered.
    let (pty_ok, transcript) = common::run_on_pty(&cache, &["update"]).unwrap();
    anyhow::ensure!(pty_ok, "gipm update on a pty failed: {transcript}");
    anyhow::ensure!(
        transcript.contains("total"),
        "the overall bar was never drawn on a pty: {transcript}",
    );

    // A repository the server refuses to serve has to fail with a message naming
    // it, not with a panic and not with an empty checkout.
    let bogus: String =
        "dependencies:\n  - version: \">=0.1\"\n    url: https://github.com/gipm-rs/definitely-not-here-xyzzy.git\n".to_string();
    fs::write("dependencies.yaml", bogus).unwrap();

    let failure: String = common::expect_failure(
        common::gipm_command(&cache).arg("update"),
        "gipm update against a missing repository",
    )
    .unwrap();
    anyhow::ensure!(
        failure.contains("definitely-not-here-xyzzy"),
        "the failure never named the missing repository: {failure}",
    );

    set_current_dir(cwd).unwrap();
    common::remove_tree(&work).unwrap();

    Ok(())
}
