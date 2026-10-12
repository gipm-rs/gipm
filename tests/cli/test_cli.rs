use std::env::{current_dir, set_current_dir};
use std::fs;
use std::path::Path;
#[path = "../common/mod.rs"]
mod common;

// The flag surface is where main.rs maps clap onto a logging::InitOptions, and
// the mapping is load-bearing in both directions: diagnostics belong on stderr
// and the result table belongs on stdout, so `gipm update 2>/dev/null` has to
// yield just the table. Every run here replays the same scenario; what varies is
// how the same work is reported.
#[test]
fn test_cli() -> anyhow::Result<()> {
    set_current_dir(Path::new("tests/cli")).unwrap();
    common::clean_generated_output()?;

    let cwd = current_dir().unwrap();
    let fixtures = cwd.join("fixtures");
    let cache = cwd.join("cache");

    let manifest_text = common::build_fixture_scenario(&fixtures, "dependencies.yaml").unwrap();
    println!("fixture manifest: {manifest_text}");

    // The table alone: stdout piped, stderr inherited so a failure is still
    // visible in the test log. Nothing but the table may reach stdout -- a bare
    // status line would make `gipm update 2>/dev/null` unparseable.
    let stdout: String = capture_stdout(&cache, &["update"])?;
    anyhow::ensure!(
        stdout.contains("+---"),
        "stdout carries no result table: {stdout}",
    );
    anyhow::ensure!(
        !stdout.contains("INFO : "),
        "a diagnostic reached stdout: {stdout}",
    );
    anyhow::ensure!(
        !stdout.contains("WARN : "),
        "a diagnostic reached stdout: {stdout}",
    );

    // -v, -q, --log-level: the same work, reported at three different weights.
    common::check(
        common::gipm_command(&cache).arg("update").arg("--verbose"),
        "gipm update -v",
    )?;
    common::check(
        common::gipm_command(&cache).arg("update").arg("-q"),
        "gipm update -q",
    )?;
    common::check(
        common::gipm_command(&cache)
            .arg("update")
            .arg("--log-level=debug"),
        "gipm update --log-level=debug",
    )?;

    // Colour and progress are the other half of InitOptions: --plain and
    // --no-progress must not change what gets resolved, only what gets drawn.
    common::check(
        common::gipm_command(&cache)
            .arg("update")
            .arg("--plain")
            .arg("--no-progress"),
        "gipm update --plain --no-progress",
    )?;
    common::check(
        common::gipm_command(&cache)
            .arg("update")
            .arg("--color=never"),
        "gipm update --color=never",
    )?;
    common::check(
        common::gipm_command(&cache)
            .arg("update")
            .arg("--color=always"),
        "gipm update --color=always",
    )?;

    // sync and clean replay the same lockfile through the same flag surface.
    common::check(
        common::gipm_command(&cache).arg("sync").arg("--verbose"),
        "gipm sync -v",
    )?;
    common::check(
        common::gipm_command(&cache).arg("clean").arg("-v"),
        "gipm clean -v",
    )?;

    // An unknown flag must be clap's error, not gipm's: it exits non-zero and
    // names the flag.
    let stderr: String = expect_failure(&cache, &["update", "--not-a-flag"])?;
    anyhow::ensure!(
        stderr.contains("not-a-flag"),
        "an unknown flag must be named by the parser: {stderr}",
    );

    // A missing subcommand is the same shape of failure.
    let stderr: String = expect_failure(&cache, &[])?;
    anyhow::ensure!(
        !stderr.is_empty(),
        "a missing subcommand must report what to do next: {stderr}",
    );

    common::check(common::gipm_command(&cache).arg("clean"), "gipm clean")?;

    fs::remove_file("dependencies.yaml").unwrap();
    common::clean_fixture_workspace(&fixtures, &cache).unwrap();

    Ok(())
}

/// Run gipm with stdout piped and stderr inherited, returning stdout -- the
/// shape that lets a test assert what reached the terminal *stream* rather than
/// what the run printed into a pipe.
fn capture_stdout(cache: &Path, args: &[&str]) -> anyhow::Result<String> {
    let mut command = common::gipm_command(cache);

    for arg in args {
        command.arg(arg.clone());
    }

    command.stdout(std::process::Stdio::piped());

    let output = command.output();

    match output {
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to run gipm {args:?}: {e:?}"));
        }
        Ok(result) => {
            anyhow::ensure!(result.status.success(), "gipm {args:?} failed: {result:?}",);

            return Ok(String::from_utf8_lossy(&result.stdout).to_string());
        }
    }
}

/// Run gipm expecting a non-zero exit, returning stderr.
fn expect_failure(cache: &Path, args: &[&str]) -> anyhow::Result<String> {
    let mut command = common::gipm_command(cache);

    for arg in args {
        command.arg(arg.clone());
    }

    command.stderr(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());

    let output = command.output();

    match output {
        Err(e) => {
            return Err(anyhow::anyhow!("Failed to run gipm {args:?}: {e:?}"));
        }
        Ok(result) => {
            anyhow::ensure!(
                !result.status.success(),
                "gipm {args:?} was expected to fail: {result:?}",
            );

            return Ok(String::from_utf8_lossy(&result.stderr).to_string());
        }
    }
}
