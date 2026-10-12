use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The renderer is a branch, not a mode: `progress::start` declines to spawn the render
// thread at all when `drawing()` is false, and every other target pipes stderr, so
// `render_loop`, `Renderer::print` and the spawn closure never exist there. `script`
// allocates a pty for the child, which is the cheapest hermetic way to take the
// drawing() branch -- the network target already does this, but it is opt-in
// (GIPM_NETWORK=1) and therefore skipped by CI and by the coverage run, leaving the
// whole render path unexercised in the tree CI actually measures.
#[test]
fn test_pty() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/pty")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let manifest_text = common::build_fixture_scenario(&fixtures, "dependencies.yaml").unwrap();
    println!("fixture manifest: {manifest_text}");

    // `-v` lifts the level to `info`, which is where the checkout and pubgrub's own
    // reasoning log -- the only lines that are ever emitted *while the bars are
    // alive*, and therefore the only ones that can reach the pending queue.
    let (ok, transcript) = common::run_on_pty(&cache, &["update", "-v"]).unwrap();
    anyhow::ensure!(ok, "gipm update on a pty failed: {transcript}");

    // The overall bar is drawn by the render thread and carries the label `total`, so
    // seeing it is the only proof that the thread ran rather than being skipped.
    anyhow::ensure!(
        transcript.contains("total"),
        "the overall bar was never drawn on a pty: {transcript}",
    );

    // A bar track, not just a label: the fill character only exists in a drawn bar.
    anyhow::ensure!(
        transcript.contains("█") || transcript.contains("─"),
        "no bar track was drawn on a pty: {transcript}",
    );

    // A log line emitted mid-phase has to survive the redraws: written straight to
    // stderr it would be wiped by the next `\e[2K`, and dropped by the queue it never
    // gets printed at all. Seeing it is the proof that the queue drained through
    // `Renderer::print` rather than losing the line on the way to a live bar block.
    anyhow::ensure!(
        transcript.contains("Checking out"),
        "a mid-phase log line never made it onto the pty: {transcript}",
    );

    // The summary table still lands on the pty, boxed, with the same header the piped
    // runs assert on -- the renderer must not have eaten the result.
    anyhow::ensure!(
        transcript.contains("package"),
        "the summary table never reached the pty: {transcript}",
    );

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    let pinned: usize = lockfile.packages.len();
    anyhow::ensure!(
        pinned == 4,
        "a pty run resolved {pinned} packages, expected 4",
    );
    common::verify_lockfile_versions(&lockfile)?;

    // `--no-progress` is the user's override and has to win over a tty: on a pty that
    // still draws, the flag would be ignored rather than honoured.
    let (quiet_ok, quiet) = common::run_on_pty(&cache, &["update", "--no-progress"]).unwrap();
    anyhow::ensure!(
        quiet_ok,
        "gipm update --no-progress on a pty failed: {quiet}"
    );
    anyhow::ensure!(
        !quiet.contains("total"),
        "--no-progress still drew the overall bar: {quiet}",
    );
    anyhow::ensure!(
        quiet.contains("package"),
        "--no-progress lost the summary table: {quiet}",
    );

    set_current_dir(cwd).unwrap();
    common::remove_tree(&fixtures).unwrap();
    common::remove_tree(&cache).unwrap();
    fs::remove_file("dependencies.yaml")?;

    Ok(())
}
