use std::env::set_current_dir;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
#[path = "../common/mod.rs"]
mod common;

#[test]
fn test_sync() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/sync")).unwrap();

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();

    let start = Instant::now();
    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("sync")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    let e1 = start.elapsed();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to sync dependencieqs: {:?}",
        result.err()
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err()
    );

    let start = Instant::now();

    // Run again - should be quick
    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("sync")
        .arg("-v")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    let e2 = start.elapsed();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to sync dependencies: {:?}",
        result.err()
    );

    anyhow::ensure!(
        e2 < (e1 / 2),
        "Expect that second update was less than half the time as first, due to caching"
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    // Clean up
    fs::remove_dir_all(Path::new(".gitvenv")).unwrap();

    lockfile_result?;

    Ok(())
}
