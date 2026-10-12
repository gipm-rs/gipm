use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The manifest this target reads is committed rather than generated: `tests/manifest/dependencies.yaml`
// is part of the repository, so the shape of a real manifest -- comments, a
// `prefix`, a `replacement`, an exact version, and a package that carries its own
// manifest -- is fixed by the file rather than assembled by a test. Only the
// repositories it names are built here, and the urls inside it are relative, so
// the file is portable across machines.
#[test]
fn test_manifest() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/manifest")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    // The committed manifest must still be there -- nothing in this target writes
    // it, and if it were missing the run below would fail with a solver error that
    // says nothing about the file being gone.
    let committed_bytes: Vec<u8> = fs::read(Path::new("dependencies.yaml")).unwrap();
    let committed: String = String::from_utf8_lossy(&committed_bytes).to_string();
    anyhow::ensure!(
        committed.contains("prefix: curl-"),
        "the committed manifest lost its prefix configuration: {committed}",
    );
    anyhow::ensure!(
        committed.contains("replacement:"),
        "the committed manifest lost its replacement configuration: {committed}",
    );
    println!("committed manifest: {committed}");

    // Build the repositories the committed manifest names. `helper` is not named
    // at the top level at all -- only app's own manifest names it -- so it can
    // only reach the lockfile if resolution recursed into the checked-out package.
    let helper = common::build_fixture_repository(&fixtures, "helper", &["0.5.0", "0.9.1"], "")?;
    let helper_url: String = helper.display().to_string();

    let app_yaml: String =
        format!("dependencies:\n  - version: \">=0.5\"\n    url: file://{helper_url}\n",);
    let app = common::build_fixture_repository(&fixtures, "app", &["1.0.0"], &app_yaml)?;
    let app_url: String = app.display().to_string();

    common::build_fixture_repository(&fixtures, "curl", &["curl-7_80_0", "curl-7_82_0"], "")?;
    common::build_fixture_repository(&fixtures, "zlib", &["v1.2.11", "v1.2.13"], "")?;
    common::build_fixture_repository(&fixtures, "base", &["0.1.0", "0.2.0"], "")?;

    // The manifest names its repositories by relative url, so the run has to be
    // launched from the directory the manifest sits in.
    common::check(common::gipm_command(&cache).arg("update"), "gipm update")?;

    let lockfile = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();

    // The solver picks the highest tag inside each range. `helper` is the fifth
    // entry and arrives only through app's own manifest.
    let expected: Vec<(String, String)> = vec![
        ("base".to_string(), "0.2.0".to_string()),
        ("curl".to_string(), "7.82.0".to_string()),
        ("zlib".to_string(), "1.2.13".to_string()),
        ("app".to_string(), "1.0.0".to_string()),
        ("helper".to_string(), "0.9.1".to_string()),
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
        "Failed to verify the lockfile: {:?}",
        lockfile_result.err(),
    );

    // Five repositories had to be fetched: the four the manifest names plus the
    // one app brought along.
    let cold_databases = common::count_cached_databases(&cache).unwrap();
    anyhow::ensure!(
        cold_databases == expected.len(),
        "Cold run cached {} databases, expected one per package ({})",
        cold_databases,
        expected.len(),
    );

    // A warm run must resolve identically: the relative urls have to be the same
    // package identity across runs, not a fresh clone each time.
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

    let warm_lock = gipm::lockfile::LockFile::from_file("gipm.lock").unwrap();
    for (name, version) in &expected {
        let found: Option<String> = warm_lock.packages.get(name).map(|p| p.version.to_string());
        anyhow::ensure!(
            found == Some(version.clone()),
            "warm run resolved {} to {:?}, expected {}",
            name,
            found,
            version,
        );
    }

    // `sync` replays the lockfile without re-resolving, which is the other half of
    // the code and has to agree with what the manifest asked for.
    common::check(common::gipm_command(&cache).arg("sync"), "gipm sync")?;
    common::verify_lockfile_versions(&lockfile)?;

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    // The manifest is committed, so it stays: only the generated checkout, the
    // lockfile, the fixture repositories and the database cache are removed.
    assert!(
        Path::new("dependencies.yaml").exists(),
        "committed manifest was removed"
    );
    fs::remove_file("gipm.lock").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}
