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
    build_fixture_repository_on(fixtures, name, "main", "", tags, dependencies_yaml)
}

/// The same repository with an explicit default branch and an optional submodule.
/// `child` names another fixture repository (`<child>.git`) that is recorded in the
/// tree as a submodule whose `.gitmodules` url is *relative* -- `child.git`, which
/// resolves against the parent's remote, the way `git` resolves it. Pass an empty
/// name for a plain package.
pub fn build_fixture_repository_on(
    fixtures: &Path,
    name: &str,
    branch: &str,
    child: &str,
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
            .arg(branch)
            .arg(&work),
        "git init",
    )?;

    if !child.is_empty() {
        attach_submodule(fixtures, name, child)?;
    }

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

/// Record `<child>.git` as a submodule of the `<parent>-work` tree, cloning it in
/// first. `git submodule add` refuses both `file://` and relative local urls
/// ("transport 'file' not allowed"), so the entry is written the way git would
/// write it: the child cloned into the mount point, `.gitmodules` carrying a
/// relative url, and both added to the index -- which leaves git recording mode
/// `160000` against the child's HEAD, exactly what a real manifest carries.
pub fn attach_submodule(fixtures: &Path, parent: &str, child: &str) -> anyhow::Result<()> {
    let work = fixtures.join(format!("{}-work", parent));
    let mount = work.join(child);

    remove_tree(&mount)?;

    check(
        fixture_git(fixtures)
            .arg("clone")
            .arg("-q")
            .arg(format!("{}.git", child))
            .arg(&mount),
        "git clone (submodule)",
    )?;

    fs::write(
        work.join(".gitmodules"),
        format!(
            "[submodule \"{}\"]\n\tpath = {}\n\turl = {}.git\n",
            child, child, child,
        ),
    )?;

    check(
        fixture_git(&work).arg("add").arg(".gitmodules"),
        "git add .gitmodules",
    )?;
    check(
        fixture_git(&work).arg("add").arg(child),
        "git add submodule",
    )?;

    Ok(())
}

/// A three-level submodule scenario: `leaf` is a plain package, `mid` carries
/// `leaf`, `top` carries `mid`. Nesting is the point -- `clone_object_into` ends by
/// walking the submodule table again, so recursion is only observable two levels
/// down. Every submodule is attached *before* the tags are made, so the tree gipm
/// resolves really carries the entry; tagging a later commit would leave the
/// resolved tree submodule-free and the test would prove nothing.
pub fn build_fixture_submodule_scenario(fixtures: &Path, manifest: &str) -> anyhow::Result<String> {
    build_fixture_repository(fixtures, "leaf", &["3.0.0"], "")?;
    build_fixture_repository_on(fixtures, "mid", "main", "leaf", &["2.0.0"], "")?;
    let top = build_fixture_repository_on(fixtures, "top", "main", "mid", &["1.0.0"], "")?;

    let top_url: String = top.display().to_string();
    let manifest_text: String =
        format!("dependencies:\n  - version: \">=1\"\n    url: file://{top_url}\n",);
    fs::write(manifest, &manifest_text)?;

    Ok(manifest_text)
}

/// The submodule entries a checkout's own index pins, as `(path, sha)` pairs --
/// `git ls-tree HEAD` rather than gix, so the assertion is against what git itself
/// reads back from the checkout gipm wrote.
pub fn pinned_submodules(dir: &Path) -> anyhow::Result<Vec<(String, String)>> {
    let output = fixture_git(dir)
        .arg("ls-tree")
        .arg("HEAD")
        .output()
        .expect("Failed to run git ls-tree");

    anyhow::ensure!(output.status.success(), "git ls-tree failed in {:?}", dir);

    let text: String = String::from_utf8_lossy(&output.stdout).to_string();
    let mut entries: Vec<(String, String)> = vec![];

    // `git ls-tree` writes `<mode> <type> <sha>\t<path>`, so the tab only
    // separates the path from the rest.
    for line in text.lines() {
        let fields: Vec<String> = line
            .split('\t')
            .map(|part| part.to_string())
            .collect::<Vec<String>>();

        if fields.len() != 2 {
            continue;
        }

        let meta: Vec<String> = fields[0]
            .clone()
            .split(' ')
            .map(|part| part.to_string())
            .collect::<Vec<String>>();

        if meta.len() == 3 && meta[0] == "160000".to_string() && meta[1] == "commit".to_string() {
            entries.push((fields[1].clone(), meta[2].clone()));
        }
    }

    Ok(entries)
}

/// Assert, walking down from `dir`, that every submodule gipm should have fetched
/// is present and sitting exactly at the commit its parent pins -- not at the child
/// repository's HEAD, which is a different claim (a shallow clone of a later commit
/// would satisfy HEAD while ignoring what the parent pinned).
pub fn verify_submodule_pins(dir: &Path) -> anyhow::Result<usize> {
    let mut checked: usize = 0;

    for (path, pinned) in pinned_submodules(dir)? {
        let mount = dir.join(&path);
        anyhow::ensure!(
            mount.join(".git").exists(),
            "submodule {} of {} was not fetched",
            path,
            dir.display().to_string(),
        );

        let output = fixture_git(&mount)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .expect("Failed to run git rev-parse");
        anyhow::ensure!(
            output.status.success(),
            "git rev-parse failed in {:?}",
            mount
        );

        let head: String = String::from_utf8_lossy(&output.stdout).trim().to_string();
        anyhow::ensure!(
            head == pinned.clone(),
            "submodule {} sits at {}, its parent pins {}",
            path,
            head,
            pinned,
        );

        checked += 1;
        checked += verify_submodule_pins(&mount)?;
    }

    Ok(checked)
}

/// Run a command that must fail: gipm reports a resolution or transport failure by
/// exiting non-zero, and `check` above would march on through a failure into a
/// confusing mismatch further down the test.
pub fn expect_failure(command: &mut Command, what: &str) -> anyhow::Result<String> {
    // `gipm_command` inherits stdio so a passing run is legible in the test log;
    // a run whose diagnostics this helper is about to assert on has to be piped
    // or `output()` would capture nothing.
    command.stderr(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());

    let output = match command.output() {
        Err(e) => return Err(anyhow::anyhow!("Failed to run {what}: {e:?}")),
        Ok(result) => result,
    };

    anyhow::ensure!(
        !output.status.success(),
        "{what} was expected to fail but exited successfully: {output:?}",
    );

    Ok(String::from_utf8_lossy(&output.stderr).to_string())
}

/// Wipe the objects of one cached database, leaving its refs behind -- the residue
/// an interrupted fetch leaves, where the directory still opens as a repository and
/// still answers `references()` but every target is missing.
pub fn corrupt_cached_database(cache: &Path) -> anyhow::Result<usize> {
    let db_root = cache.join(".gipm/db");

    let entries: fs::ReadDir = match fs::read_dir(&db_root) {
        Err(_) => return Err(anyhow::anyhow!("no database cache at {:?}", db_root)),
        Ok(entries) => entries,
    };

    let dirs: Vec<PathBuf> = entries
        .map(|entry| match entry {
            Ok(dir_entry) => dir_entry.path(),
            Err(_) => PathBuf::new(),
        })
        .filter(|path| path.is_dir())
        .collect::<Vec<PathBuf>>();

    anyhow::ensure!(
        !dirs.is_empty(),
        "no cached database to corrupt at {:?}",
        db_root,
    );

    remove_tree(&dirs[0].join("objects"))?;

    Ok(1)
}

/// Run gipm with both streams piped and report `(exit_zero, stdout, stderr)`.
/// `check` above lets the child inherit stdio, which is what makes a passing run
/// legible in the test log; an assertion about *what a run printed* needs the
/// opposite -- the streams have to be captured, and a non-zero exit is a
/// legitimate outcome here rather than a failure of the test.
pub fn run_captured(cache: &Path, args: &[&str]) -> anyhow::Result<(bool, String, String)> {
    let mut command = gipm_command(cache);

    for arg in args {
        command.arg(arg.clone());
    }

    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let output = match command.output() {
        Err(e) => return Err(anyhow::anyhow!("Failed to run gipm {args:?}: {e:?}")),
        Ok(result) => result,
    };

    Ok((
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

/// Replace the first `commit = "<sha>"` entry of a lockfile with `commit`, leaving
/// the rest of the file byte-identical -- the residue a hand-edited or half-written
/// lockfile leaves behind. `sync` parses that field into a `gix::ObjectId`, so this
/// is the input it has to report rather than trust.
pub fn corrupt_lockfile_commit(lockfile: &str, commit: &str) -> anyhow::Result<usize> {
    let bytes: Vec<u8> = fs::read(lockfile)?;
    let text: String = String::from_utf8_lossy(&bytes).to_string();

    let marker: String = "commit = \"".to_string();
    let start: usize = match text.find(marker.as_str()) {
        None => return Err(anyhow::anyhow!("no commit entry in {lockfile}")),
        Some(at) => at + marker.len(),
    };

    let tail: String = text[start..].to_string();
    let offset: usize = match tail.find('"') {
        None => return Err(anyhow::anyhow!("unterminated commit value in {lockfile}")),
        Some(at) => at,
    };

    let rewritten: String = format!(
        "{}{}{}",
        text[..start].to_string(),
        commit,
        tail[offset..].to_string()
    );
    fs::write(lockfile, rewritten)?;

    Ok(1)
}

/// Run a fixture git command in `dir`, returning trimmed stdout.
pub fn fixture_run(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let mut command = fixture_git(dir);

    for arg in args {
        command.arg(arg.clone());
    }

    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let output = match command.output() {
        Err(e) => return Err(anyhow::anyhow!("Failed to run git {args:?}: {e:?}")),
        Ok(result) => result,
    };

    anyhow::ensure!(output.status.success(), "git {args:?} failed in {dir:?}",);

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Give an already-resolved fixture repository a new commit and tag -- upstream
/// moving after the fact. The commit reuses the base commit's tree, so only the
/// commit object is new: a checkout that already exists cannot find it on disk and
/// has to fetch it out of its database, which is the path a fresh clone (hardlinking
/// the database's whole object store) never takes.
pub fn add_upstream_tag(
    fixture: &Path,
    name: &str,
    tag: &str,
    based_on: &str,
) -> anyhow::Result<String> {
    let bare = fixture.join(format!("{name}.git"));
    anyhow::ensure!(
        bare.exists(),
        "no fixture repository at {}",
        bare.display().to_string()
    );

    let location: String = bare.display().to_string();
    let query: String = format!("{based_on}^{{tree}}");
    let tree: String = fixture_run(&bare, &["rev-parse", query.as_str()])?;
    anyhow::ensure!(!tree.is_empty(), "no tree for {based_on} in {location}",);

    let commit: String = fixture_run(
        &bare,
        &["commit-tree", tree.as_str(), "-m", "upstream drift"],
    )?;
    anyhow::ensure!(
        !commit.is_empty(),
        "commit-tree produced no object in {location}",
    );

    fixture_run(&bare, &["tag", tag, commit.as_str()])?;

    Ok(commit)
}
/// Run the CLI under `script`, which allocates a pty for the child so the progress
/// renderer takes its drawing() branch rather than the piped branch. Returns the
/// exit status plus everything the pty echoed (stdout and stderr both land on it).
pub fn run_on_pty(cache: &Path, args: &[&str]) -> anyhow::Result<(bool, String)> {
    let mut inner: String = env!("CARGO_BIN_EXE_gipm").to_string();
    for arg in args {
        inner = format!("{inner} {arg}");
    }

    let mut command = Command::new("script");
    command.env("HOME", cache);
    command.arg("-q");
    command.arg("-e");
    command.arg("/dev/null");
    command.arg("-c");
    command.arg(inner);
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let output = match command.output() {
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to run gipm {args:?} on a pty: {e:?}"
            ));
        }
        Ok(result) => result,
    };

    let transcript: String = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    );

    Ok((output.status.success(), transcript))
}
