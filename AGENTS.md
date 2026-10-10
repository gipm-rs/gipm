# gipm — Git Package(like) Manager

Instructions for AI coding agents working in this repository. Read this file before changing
anything; the "Invariants" section lists rules that look optional but are not.

## What this is

`gipm` is a git package manager for languages with no native package system (C/C++, Fortran).
It reads a `dependencies.yaml` manifest of git URLs plus semver ranges, resolves the graph with
the same pubgrub solver `uv` uses, and checks the resolved packages out into `.gitvenv`. It exists
to replace nested git submodules, not to replace `cargo`/`npm`/`uv` inside ecosystems that already
have one.

## Commands

```sh
cargo build --release                 # the CLI at target/release/gipm
cargo run --release -- update         # run the CLI (pass args after --)
cargo test --all-features             # all four integration targets
cargo test --test test_update         # one target: test_lockfile | test_update | test_sync | test_clean
cargo clippy --all-features --all-targets --warnings-as-errors=src/*   # CI gate
cargo fmt --all
```

Test caveats — the suite is hermetic, but it still shells out:
- Each target `chdir`s into its own `tests/<name>/` directory and shells out to
  `CARGO_BIN_EXE_gipm` against **fixture repositories built on demand** by
  `common::build_fixture_scenario` (tiny bare repos reached over `file://`). No network,
  no upstream to move; the resolved versions in `test_update` are assertions, not drift.
- `tests/update/dependencies.yaml` and `tests/sync/gipm.lock` are **generated** by that
  builder and removed at the end of a passing run — they are not checked in, and
  `tests/*/fixtures/` plus `tests/*/cache/` are gitignored scaffolding.
- Every run gets its own database cache (`HOME` is pointed at `tests/<name>/cache`), so a
  test can neither read nor poison the host's `~/.gipm/db`.
- `tests/common/mod.rs` holds shared assertions (`verify_lockfile_versions`, …) and is pulled in
  with `#[path = "../common/mod.rs"]`; do not convert it to a package.
- Coverage excludes `tests/` and `third_party/` — do not "fix" clippy warnings in
  `src/third_party/semver_pubgrub/` (it is a vendored copy, `#![allow(clippy::all)]` at its
  module root).

## Architecture

| Path | Role |
| --- | --- |
| `src/main.rs` | clap CLI surface; maps flags (`-v`, `-q`, `--log-level`, `--color`, `--plain`, `--no-progress`) to a `logging::InitOptions`. |
| `src/lib.rs` | Library entry point: `install_dependencies()` (update), `sync_dependencies()` (sync), `clean()`. |
| `src/dependency.rs` | Parses `dependencies.yaml` into `DependencySpecification` (url, version range, `prefix`, `replacement`). |
| `src/git.rs` | `GitPackage`/`PackageUrl`: clone, tag discovery, sha resolution, worktree checkout, submodule handling via `gix`. |
| `src/resolver.rs` | `GitDependencyProvider` feeding `pubgrub::resolve` over semver `Ranges`. |
| `src/lockfile.rs` | `gipm.lock` serialize/deserialize (`LockFile`, `LockFilePackage`). |
| `src/logging.rs` | The `log` facade: level/colour resolution, and the summary **table** on stdout. |
| `src/progress.rs` | The **only** place `prodash`, `indicatif` and `console` are referenced. |
| `src/third_party/` | Vendored upstream code (`semver_pubgrub/`) — treat as read-only. |
| `dependencies.yaml` | Primary input manifest; `gipm.lock` is the generated output. |
| `.gitvenv/` | Generated checkout directory (gitignored); never hand-edit it. |

Git work is driven entirely by [`gix`](https://github.com/GitoxideLabs/gitoxide) in-process —
there is no shelled-out `git` except for recursive submodule init, which still falls back to the
`git` binary because `gix` submodule support is incomplete.

## Invariants

Logging and progress are split by design; both are load-bearing.

`logging.rs`
- Diagnostics go to **stderr**, the result summary table goes to **stdout** and nothing else.
  `gipm update 2>/dev/null` must yield just the table. Never use bare `println!`/`eprintln!` for
  status reporting.
- The table is boxed (`┌┬┐` styled, `+` plain), padded by visible width, fitted to the terminal by
  truncating widest columns with `…` **only when styled** (redirected output stays lossless), and
  drops any column with no data anywhere. The `commit` column carries the resolved sha, so a report
  shows tag *and* commit.
- Cell colours come from the same palette as the bars, applied **per column** (`COL_STYLES`):
  bold package, cyan version, grey tag/sha, green or yellow status. The header line takes each
  column's style rather than a blanket bold, and the vertical rules carry the same grey as the
  horizontal ones — one weight per column across the whole box, so no line of the table reads
  heavier than another.

`progress.rs`
- `prodash` is the data model (gix progress callbacks are typed against its tree items);
  `indicatif` draws the bars — one overall bar, one bar per package, a braille spinner for
  unsized tasks.
- Bars are keyed by the prodash item, never by position; bar lengths/counters are monotonic.
- A bar's track is built from **stages, not raw counters** (`stage_of` folds every sized item into
  `STAGE_TICKS` and sums the weights): gix reports a fetch as thousands of files and the step
  around it as three actions, so a summed model reads 100% the moment the fetch finishes while
  the checkout that takes far longer has not even started. Unsized items contribute nothing.
- A running bar never reads 100% — every stage it knows about can be finished while the next one
  has not been discovered yet, and a full green bar there tells the user the work is over when it
  is not. The overall bar holds the same line while any bar is still moving.
- When a bar's track grows (gix reports stages lazily) the old fill is re-expressed against the
  new track before the counter is compared, so the fill never slides backwards.
- Once `set_expected` hands the overall bar a real denominator, `set_style(overall_style)` must be
  re-applied: the spinner style is sticky and the rule and the percentage then are not drawn at all.
- The overall bar's denominator comes from `progress::start(expected)` / `progress::set_expected(n)`
  and its numerator from `progress::task_done(name)`. The prodash tree only holds *currently
  running* work (items drop out of scope), so it can **never** be a denominator.
- Use `progress::start(...)`, `progress::child(...)`, `progress::subchild(...)`.
- Never call `ProgressBar::enable_steady_tick` on a bar living in a `MultiProgress` — its ticker
  thread redraws that single bar and prints a stray duplicate line; the render thread ticks instead.
- Never write to `stderr` directly while bars are alive — go through `progress::write_line` so the
  bar block is never scribbled over.
- In indicatif templates only `:` separates key from width/style, so `{msg.cyan}` parses as the key
  `msg.cyan` and renders nothing. Write `{msg:.cyan}`.

`git.rs` — the database cache
- A cached database directory is **not** valid because it exists. It is usable only when it
  opens as a repository *and* some reference still resolves to an object we hold
  (`database_is_usable`). An interrupted fetch leaves a directory that opens happily — with
  objects but no refs, or refs in `packed-refs` whose targets were never downloaded — and
  trusting that is what made later runs report "Object … does not exist in the database" for
  a sha upstream still publishes. Anything that needs a database calls
  `ensure_usable_database()`, which removes the residue and re-clones; `clone_dependency_database`
  takes the same guard on its own "existing database" branch.

## Workflow after touching dependency handling

Always re-resolve and verify, don't eyeball:

1. `gipm update` (or `gipm sync` to replay an existing `gipm.lock`).
2. Confirm `.gitvenv` state matches the lockfile — the test targets' `verify_lockfile_versions`
   helper is the check the CI already uses.

## Known limitations (do not "fix" by surprise)

- **Submodules**: nested submodules are the pain point this tool replaces; if a dependency carries
  its own dependencies they can appear in both `.gitvenv` and as submodules, which is currently
  unavoidable.
- **Scope**: `gipm` is general-purpose and must not shadow a real package manager inside a supported
  ecosystem.
- **Versioning**: relies on cargo-style [version requirement syntax](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#version-requirement-syntax) and on upstream repos keeping consistent tag formats.
- `todo.md` tracks open bugs (weak prefix finder, exact-version `1.2.13` matching `>=`, submodule
  clone permissions, sync-then-update pulling extra tag refs). Read it before working on those areas,
  and don't silently change behaviour that a bug entry describes as intended-but-rough.
