use std::path::Path;
use std::process::Command;

pub fn verify_lockfile_versions(lockfile: &gipm::lockfile::LockFile) -> anyhow::Result<()> {
    for package in lockfile.packages.values() {
        let tmp_gitpackage = gipm::git::GitPackage::new(
            gipm::git::PackageUrl::GitUrl(package.source.clone()),
            None,
            None,
        );
        let package_name = tmp_gitpackage.name();
        let package_path = Path::new(".gitvenv").join(&package_name);
        anyhow::ensure!(
            package_path.exists(),
            "Package directory {} does not exist",
            package_name
        );

        let package_commit = &package.commit;

        let output = Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .current_dir(package_path)
            .output()
            .expect("Failed to run git command");

        anyhow::ensure!(
            String::from_utf8_lossy(&output.stdout).trim() == package_commit,
            "Commit hash for package {} does not match. Expected: {}, Found: {}",
            package_name,
            package_commit,
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }

    Ok(())
}
