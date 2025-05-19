use std::env::set_current_dir;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;
#[path = "../common/mod.rs"]
mod common;

#[test]
fn test_update() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/update")).unwrap();

    let start = Instant::now();
    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("update")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    let e1 = start.elapsed();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to install dependencies: {:?}",
        result.err()
    );

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err()
    );

    assert!(
        Path::new(".gitvenv").exists(),
        "Virtual environment was not created"
    );

    // Run again - should be quick

    let start = Instant::now();
    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("update")
        .arg("--verbose")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    let e2 = start.elapsed();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to install dependencies: {:?}",
        result.err()
    );

    assert!(
        Path::new(".gitvenv").exists(),
        "Virtual environment was not created"
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err()
    );

    anyhow::ensure!(
        e2 < (e1 / 2),
        "Expect that second update was less than half the time as first, due to caching"
    );

    fs::remove_dir_all(Path::new(".gitvenv")).unwrap();

    assert!(Path::new("gipm.lock").exists(), "Lockfile was not created");
    fs::remove_file("gipm.lock").unwrap();

    Ok(())
}
