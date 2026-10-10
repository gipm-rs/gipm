use std::env::current_dir;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
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
            package_name,
        );

        // Without this guard `git rev-parse HEAD` walks out of a missing checkout and
        // answers with the *test harness's* repository, which reports a sha that has
        // nothing to do with the package and makes the mismatch below unreadable.
        anyhow::ensure!(
            package_path.join(".git").exists(),
            "Package directory {} is not a git checkout",
            package_name,
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
            String::from_utf8_lossy(&output.stdout).trim(),
        );
    }

    Ok(())
}

/// Check that a spawned command ran and exited successfully. The exit status is
/// what matters: `output()` succeeding only means the process started, and a gipm
/// run that exits non-zero still prints its whole report, so the failure has to be
/// turned into an assertion here or the test marches on into a confusing mismatch.
pub fn check(command: &mut Command, what: &str) -> anyhow::Result<()> {
    let output = command.output();

    match output {
        Err(e) => anyhow::bail!("Failed to run {what}: {e:?}"),
        Ok(result) => {
            anyhow::ensure!(
                result.status.success(),
                "{what} exited with an error: {result:?}",
            );
            Ok(())
        }
    }
}

/// The gipm binary, with `HOME` pointed at `cache` so its database cache lives in
/// `<cache>/.gipm/db` rather than the host's `~/.gipm/db`, and with a committer
/// identity set: gix writes a reflog when it checks a package out, and that needs
/// one — the same reason CI exports `git config user.name`/`user.email` before
/// running the suite.
pub fn gipm_command(cache: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gipm"));
    command.env("HOME", cache);
    command.env("GIT_AUTHOR_NAME", "gipm fixture");
    command.env("GIT_AUTHOR_EMAIL", "fixture@gipm.dev");
    command.env("GIT_COMMITTER_NAME", "gipm fixture");
    command.env("GIT_COMMITTER_EMAIL", "fixture@gipm.dev");
    command.stdout(std::process::Stdio::inherit());
    command.stderr(std::process::Stdio::inherit());
    command
}

/// A `git` invocation carrying a pinned author, committer and date, so fixture
/// commits are byte-identical across runs and a test can generate a lockfile and
/// replay it through `sync` while still comparing real shas.
pub fn fixture_git(cwd: &Path) -> Command {
    let mut command = Command::new("git");
    command.env("GIT_AUTHOR_NAME", "gipm fixture");
    command.env("GIT_AUTHOR_EMAIL", "fixture@gipm.dev");
    command.env("GIT_COMMITTER_NAME", "gipm fixture");
    command.env("GIT_COMMITTER_EMAIL", "fixture@gipm.dev");
    command.env("GIT_AUTHOR_DATE", "2024-01-01T00:00:00 +0000");
    command.env("GIT_COMMITTER_DATE", "2024-01-01T00:00:00 +0000");
    command.current_dir(cwd);
    command
}

/// Remove the generated checkout and lockfile from the current directory so a run
/// starts from the same clean state CI sees. A run that failed part way through
/// leaves both behind, and a leftover `.gitvenv` makes the next `update` see a
/// dirty checkout and refuse to move it.
pub fn clean_generated_output() -> anyhow::Result<()> {
    let cwd = current_dir().unwrap();

    remove_tree(&cwd.join(".gitvenv"))?;

    let lockfile = cwd.join("gipm.lock");
    if lockfile.exists() {
        fs::remove_file(lockfile)?;
    }

    Ok(())
}

/// Count the database directories gipm has cached under `<cache>/.gipm/db`.
/// This is the observable half of the cache: a run that trusted an unusable
/// database would fail before leaving one behind, and one that had to rebuild
/// would leave a wiped directory. Timing assertions at fixture scale measure
/// process start-up, not caching, so the tests assert this instead.
pub fn count_cached_databases(cache: &Path) -> anyhow::Result<usize> {
    let db_root = cache.join(".gipm/db");

    let entries: fs::ReadDir = match fs::read_dir(&db_root) {
        Err(_) => return Ok(0),
        Ok(entries) => entries,
    };

    let databases: usize = entries
        .map(|entry| match entry {
            Ok(dir_entry) => dir_entry.path().is_dir(),
            Err(_) => false,
        })
        .filter(|is_dir| *is_dir)
        .count();

    Ok(databases)
}

/// Remove a tree if it is present; the fixture workspace is rebuilt on every run,
/// and a run that failed part way through leaves one behind.
pub fn remove_tree(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }

    Ok(())
}

/// Build one fixture repository carrying `tags` as annotated tags, one commit per
/// tag, and `dependencies_yaml` in every tree (empty for a leaf package, which is
/// what the resolver has to tolerate). The bare clone is what a `file://` URL in a
/// manifest points at; the working directory is only scaffolding.
pub fn build_fixture_repository(
    fixtures: &Path,
    name: &str,
    tags: &[&str],
    dependencies_yaml: &str,
) -> anyhow::Result<PathBuf> {
    let work = fixtures.join(format!("{name}-work"));
    let bare = fixtures.join(format!("{name}.git"));

    remove_tree(&work)?;
    remove_tree(&bare)?;
    fs::create_dir_all(fixtures)?;
    check(
        fixture_git(fixtures)
            .arg("init")
            .arg("-q")
            .arg("-b")
            .arg("main")
            .arg(&work),
        "git init",
    )?;

    for tag in tags {
        fs::write(work.join("VERSION"), format!("{tag}\n"))?;
        check(fixture_git(&work).arg("add").arg("VERSION"), "git add")?;
        if !dependencies_yaml.is_empty() {
            fs::write(work.join("dependencies.yaml"), dependencies_yaml)?;
            check(
                fixture_git(&work).arg("add").arg("dependencies.yaml"),
                "git add dependencies.yaml",
            )?;
        }
        check(
            fixture_git(&work)
                .arg("commit")
                .arg("-q")
                .arg("-m")
                .arg(tag),
            "git commit",
        )?;
        check(
            fixture_git(&work)
                .arg("tag")
                .arg("-a")
                .arg(tag)
                .arg("-m")
                .arg(tag),
            "git tag",
        )?;
    }

    check(
        fixture_git(fixtures)
            .arg("clone")
            .arg("--bare")
            .arg("--quiet")
            .arg(&work)
            .arg(&bare),
        "git clone --bare",
    )?;
    remove_tree(&work)?;

    Ok(bare)
}

/// Build the fixture scenario and write the manifest that points at it into
/// `manifest` (relative to the caller's cwd). The four packages cover every piece
/// of version handling the solver has to get right without a network:
///
/// - `alpha` has three bare semver tags and a `dependencies.yaml` of its own, so
///   resolution has to recurse into a package's own manifest;
/// - `beta` tags carry a `v` prefix, which the tag parser has to see through;
/// - `gamma` tags are `curl-1_0_0` shaped, i.e. a prefix *and* `_` separators
///   rewritten by `replacement`, the machinery the real curl manifest needed;
/// - `delta` is a plain leaf.
///
/// Returns the manifest text so a test can log what it actually asked for.
pub fn build_fixture_scenario(fixtures: &Path, manifest: &str) -> anyhow::Result<String> {
    let beta = build_fixture_repository(fixtures, "beta", &["v0.5.0", "v0.9.1"], "")?;
    let gamma = build_fixture_repository(fixtures, "gamma", &["curl-1_0_0", "curl-1_2_0"], "")?;

    let beta_url: String = beta.display().to_string();
    let gamma_url: String = gamma.display().to_string();

    let alpha_yaml: String = format!(
        "dependencies:\n  - version: \">=0.5\"\n    url: file://{beta_url}\n  - version: \"^1.2\"\n    url: file://{gamma_url}\n    prefix: curl-\n    replacement:\n      - [\"_\", \".\"]\n",
    );
    let alpha =
        build_fixture_repository(fixtures, "alpha", &["1.0.0", "1.2.0", "2.0.0"], &alpha_yaml)?;
    let delta = build_fixture_repository(fixtures, "delta", &["0.1.0"], "")?;

    let alpha_url: String = alpha.display().to_string();
    let delta_url: String = delta.display().to_string();

    let manifest_text: String = format!(
        "dependencies:\n  - version: \"~1\"\n    url: file://{alpha_url}\n  - version: \"^0.1\"\n    url: file://{delta_url}\n",
    );
    fs::write(manifest, &manifest_text)?;

    Ok(manifest_text)
}

/// Remove the fixture repositories and the isolated database cache. Kept separate
/// from the scenario builder so a failing test can be re-run against the state it
/// left behind.
pub fn clean_fixture_workspace(fixtures: &Path, cache: &Path) -> anyhow::Result<()> {
    remove_tree(fixtures)?;
    remove_tree(cache)?;

    Ok(())
}
