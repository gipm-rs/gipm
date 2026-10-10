use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The fixture scenario is hermetic: four local repositories built on demand, and
// the databases cached under a per-test HOME. Nothing here touches the network, so
// the resolved versions below are assertions rather than something upstream can
// move under us.
#[test]
fn test_update() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/update")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let manifest_text = common::build_fixture_scenario(&fixtures, "dependencies.yaml").unwrap();
    println!("fixture manifest: {manifest_text}");

    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    anyhow::ensure!(
        Path::new(".gitvenv").exists(),
        "Virtual environment was not created",
    );

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();

    // The solver has to pick the highest tag inside each range, and it has to
    // discover beta and gamma only by recursing into alpha's own dependencies.yaml.
    let expected: Vec<(String, String)> = vec![
        ("alpha".to_string(), "1.2.0".to_string()),
        ("beta".to_string(), "0.9.1".to_string()),
        ("gamma".to_string(), "1.2.0".to_string()),
        ("delta".to_string(), "0.1.0".to_string()),
    ];
    anyhow::ensure!(
        lockfile.packages.len() == expected.len(),
        "Expected {} packages, found {}",
        expected.len(),
        lockfile.packages.len(),
    );
    for (name, version) in &expected {
        let found: Option<String> = lockfile.packages.get(name).map(|p| p.version.to_string());
        anyhow::ensure!(
            found == Some(version.clone()),
            "Package {} resolved to {:?}, expected {}",
            name,
            found,
            version,
        );
    }

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err(),
    );

    // The first run had no cache, so it had to build one database per package.

    let cold_databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        cold_databases == expected.len(),
        "Cold run cached {} databases, expected one per package ({})",
        cold_databases,
        expected.len(),
    );

    // Run again - the databases are cached under `cache`, so nothing is rebuilt.
    // Timing is not asserted: at fixture scale both runs are dominated by process
    // start-up, which is what made the old assertion flaky.

    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update --verbose",
    )?;

    let warm_databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        warm_databases == cold_databases,
        "Second run changed the database cache: cold {}, warm {}",
        cold_databases,
        warm_databases,
    );

    anyhow::ensure!(
        Path::new(".gitvenv").exists(),
        "Virtual environment was not created",
    );

    let lockfile_result = common::verify_lockfile_versions(&lockfile);

    anyhow::ensure!(
        lockfile_result.is_ok(),
        "Failed to sync dependencies: {:?}",
        lockfile_result.err(),
    );

    fs::remove_dir_all(Path::new(".gitvenv")).unwrap();

    assert!(Path::new("gipm.lock").exists(), "Lockfile was not created");
    fs::remove_file("gipm.lock").unwrap();
    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
