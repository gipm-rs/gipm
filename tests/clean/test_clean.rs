use std::env::set_current_dir;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_update() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/clean")).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("clean")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to clean dependencies: {:?}",
        result.err()
    );

    anyhow::ensure!(
        !Path::new(".gitvenv").exists(),
        "Virtual environment was cleaned"
    );

    // run again, make sure no errors
    let result = Command::new(env!("CARGO_BIN_EXE_gipm"))
        .arg("clean")
        .arg("-v")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .output();

    anyhow::ensure!(
        result.is_ok(),
        "Failed to clean dependencies: {:?}",
        result.err()
    );

    let venv_path = Path::new(".gitvenv");

    fs::create_dir_all(venv_path).unwrap();

    fs::File::create(venv_path.join(".gitignore")).expect("Failed to create .gitignore");

    Ok(())
}
