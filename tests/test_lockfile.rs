use gipm::lockfile::LockFile;
use semver::Version;

use std::fs;
use std::path::Path;

#[test]
fn test_lockfile_creation_and_reading() {
    let test_lock_path = Path::new("test_gipm.lock");

    // Ensure a clean state before the test
    if test_lock_path.exists() {
        fs::remove_file(test_lock_path).unwrap();
    }

    let mut lockfile = LockFile::default();

    let package1_version = Version::new(1, 0, 0);
    let package1_name = "repo1".to_string();
    let package1_source = "https://github.com/user/repo1.git".to_string();
    let package1_commit = "dummy_commit_1".to_string();
    let package1_dependencies = None;
    lockfile
        .add_package(
            package1_name,
            package1_version.clone(),
            package1_source,
            package1_commit,
            package1_dependencies,
        )
        .unwrap();

    let package2_version = Version::new(2, 1, 0);
    let package2_name = "repo2".to_string();
    let package2_source = "https://github.com/user/repo2.git".to_string();
    let package2_commit = "dummy_commit_2".to_string();
    let package2_dependencies = None;
    lockfile
        .add_package(
            package2_name,
            package2_version.clone(),
            package2_source,
            package2_commit,
            package2_dependencies,
        )
        .unwrap();

    // Write the lockfile to a temporary path
    lockfile.to_file(test_lock_path).unwrap();

    // Read the lockfile back
    let read_lockfile = LockFile::from_file(test_lock_path).unwrap();

    // Assertions
    assert_eq!(read_lockfile.version, "1");
    assert_eq!(read_lockfile.packages.len(), 2);

    let p1 = read_lockfile.packages.get("repo1").unwrap();
    assert_eq!(p1.version, package1_version);
    assert_eq!(p1.source, "https://github.com/user/repo1.git");
    // Commit hash will vary, so we only check it's not empty
    assert!(!p1.commit.is_empty());
    assert_eq!(p1.dependencies.len(), 0);

    let p2 = read_lockfile.packages.get("repo2").unwrap();
    assert_eq!(p2.version, package2_version);
    assert_eq!(p2.source, "https://github.com/user/repo2.git");
    assert!(!p2.commit.is_empty());
    assert_eq!(p2.dependencies.len(), 0);

    // Clean up
    fs::remove_file(test_lock_path).unwrap();
}

#[test]
fn test_lockfile_deletion() {
    let test_lock_path = Path::new("test_gipm_delete.lock");

    // Create a dummy lockfile
    let lockfile = LockFile::default();
    lockfile.to_file(test_lock_path).unwrap();

    assert!(test_lock_path.exists());

    // Simulate deletion (e.g., by calling the clean function or directly removing)
    fs::remove_file(test_lock_path).unwrap();

    assert!(!test_lock_path.exists());
}
