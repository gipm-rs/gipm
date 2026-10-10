# Logging & Progress Overhaul — Plan

Status: **complete** (incl. §14 follow-up) · Scope: `src/lib.rs`, `src/git.rs`, `src/resolver.rs`, `src/dependency.rs`, `src/main.rs`, `src/third_party/semver_pubgrub/mod.rs`, `Cargo.toml`, docs
Baseline commit: pre-change (line numbers below are from the pre-change tree and will drift as steps land)

## Plan Steps (13)

- [x] 1. Inventory pass (no code changes) — inventory tables below
- [x] 2. Decide the crate stack and record it: add `log`, `crossterm`; keep `prodash` (trimmed features) — `log-level` does not exist on crates.io, substituted (§2)
- [x] 3. New module `src/logging.rs` (registered in `src/lib.rs`): `init()`, level resolution, rich formatter, symbol helpers, summary renderer — done, `log::Log` impl + `SummaryRow`/`render_summary`
- [x] 4. New module `src/progress.rs` — the prodash adapter that hides prodash from call sites — done: `start()` returns a RAII `ProgressHandle`, `child()`, `subchild()`, `set_enabled()`; disabled mode starts no render thread
- [x] 5. Delete the `VERBOSE` `Lazy` hack (`src/lib.rs:56`) and `use crate::{PROGRESS, VERBOSE}` (`src/git.rs:2`) — done, `once_cell`/`Lazy` imports dropped
- [x] 6. Mechanical sweep of the 33 direct print sites per the Inventory table (level mapping) — done (remaining `println!`s are inside `#[test]` bodies only)
- [x] 7. Restructure command output into phases + a shared summary table — done (`render_summary` for sync + update)
- [x] 8. CLI surface in `src/main.rs`: `-v` countable, `-q`, `--log-level`, `--plain`/`--no-progress`, `--color` — done (`--verbose` kept as the long form so existing tests still parse)
- [x] 9. Progress-bar semantics under parallelism (rayon `par_iter` + RAII renderer shutdown) — done: level filter `1..=1`, no timestamp/throughput/hide-cursor, `ProgressHandle` drop shuts the renderer down
- [x] 10. Test/robustness work: unit tests for level resolution, formatter, table alignment; double-`init()` no-op — 4 new unit tests in `src/logging.rs`, all green; integration tests still pass
- [x] 11. Windows verification: `--plain` + colour runs on the Windows console, no mojibake, crossterm cursor behaviour — verified: 0 ESC sequences under `--plain`/auto-when-piped, 0 non-ASCII bytes, `--color always` emits colour
- [x] 12. Docs: `README.md` "Use" flags, `CLAUDE.md` architecture note, `todo.md` deferrals — done
- [x] 13. Implementation order (lowest risk first): (a) logging crate + init → (b) print sweep → (c) progress adapter + feature trim → (d) summary table + CLI flags → (e) docs — followed
- [x] 14. Follow-up: replace the prodash *line renderer* with `indicatif` bars (overall bar + one per package), route log lines through the renderer so the cursor stops jumping — done, see §14

---

## 0. Constraints & why this can't be a clean-slate swap

Three unrelated, half-finished mechanisms exist today:

1. **`VERBOSE` hack** — `src/lib.rs:56`, `once_cell::sync::Lazy<bool>` that re-parses `std::env::args()` for `-v`/`--verbose`. Bypasses clap entirely, so flag position is accidental; checked via `if *VERBOSE { println!(…) }` in 12 places.
2. **Bare `println!`/`eprintln!`** — 33 first-party sites + 6 vendored sites, mixing results, warnings, errors and debug noise with no level, no stream policy, no wrapping.
3. **`prodash` progress tree** — global tree root + a line renderer with `timestamp`/`throughput`/`hide_cursor` on, and ~60 hand-managed `add_child`/`init`/`inc`/`done`/`fail`/`drop` calls threaded through `src/git.rs` as `&mut Item` parameters.

**Hard constraint:** `gix` progress callbacks are typed against `gix::progress::prodash::Progress` / `gix::progress::prodash::tree::Item` (`src/git.rs:5`, `src/git.rs:6`; `gix` is built with the `progress-tree` feature). **prodash cannot be removed as a dependency.** It becomes an implementation detail confined to `src/progress.rs`; no other module may name `prodash::*`.

**Secondary constraint:** `tests/**` call the library API directly (`tests/common/mod.rs`, `tests/update/test_update.rs`, …). Logger init must be idempotent/no-op-safe so library use never panics on "logger already initialized".

---

## 1. INVENTORY (step 1 — complete)

### A. Direct print sites — 33 first-party + 6 vendored = 39

Target level legend: `E`=error `W`=warn `I`=info(user result) `D`=debug(`-vv`) `T`=trace(`-vvv`) `SUM`=summary-table row `FOOT`=footer line

#### `src/lib.rs` — 13

| # | Line | Statement (abridged) | Guard | Target |
|---|------|----------------------|-------|--------|
| 1 | 110 | `Updating checkout for {} at commit {}` | `if *VERBOSE` @109 | `D` |
| 2 | 139 | `Synced dependencies:` | — | `SUM` header |
| 3 | 144 | `  ❗ {}: {version} - dirty workspace` | — | `SUM` row (dirty) |
| 4 | 146 | `  ✅ {}: {version}` | — | `SUM` row (ok) |
| 5 | 150 | `eprintln!("❌ Failed to check out {name} at version {version}: {e:?}")` | — | `E` |
| 6 | 158 | `✅ All dependencies synced successfully!` | — | `FOOT` |
| 7 | 172 | `Deleted .gitvenv directory` | — | `I` |
| 8 | 215 | `Checking out {} at version {version}` | `if *VERBOSE` @214 | `D` |
| 9 | 230 | `Resolved dependencies:` | — | `SUM` header |
| 10 | 234 | `  ❗ {}: {version} (tag {}) - dirty workspace` | — | `SUM` row (dirty) |
| 11 | 240 | `  ✅ {}: {version} (tag {})` | — | `SUM` row (ok) |
| 12 | 286 | `✅ All dependencies resolved and checked out successfully!` | — | `FOOT` |
| 13 | 287 | `🔒 Lockfile updated at gipm.lock` | — | `I` |

#### `src/git.rs` — 12

| # | Line | Statement (abridged) | Guard | Target |
|---|------|----------------------|-------|--------|
| 1 | 340 | `Extracted version {version} from tag {tag}` | `if *VERBOSE` @339 | `T` |
| 2 | 353 | `Failed to extract version from tag: {tag}` | `else if *VERBOSE` @352 | `T` |
| 3 | 445 | `Database path for {}: {:?}` | `if *VERBOSE` @444 | `D` |
| 4 | 450 | `Found existing database at {path:?}` | `if *VERBOSE` @449 | `D` |
| 5 | 564 | `Warning: Repository at {checkout_dir:?} has uncommitted changes, proceeding anyway` | **none** | `W` |
| 6 | 639 | same warning, ref-fetch path | **none** | `W` |
| 7 | 1027 | `Removed file: {file_path}` | **none** (per-file) | `T` |
| 8 | 1033 | `Removed directory: {file_path}` | **none** (per-file) | `T` |
| 9 | 1087 | `Updated permissions for {file_path}: {cur} -> {exp}` (POSIX) | `if *VERBOSE` @1084 | `D` |
| 10 | 1112 | `Updated permissions … readonly -> writable (executable)` (Windows) | `if *VERBOSE` @1111 | `D` |
| 11 | 1121 | `Updated permissions … writable -> readonly (not executable)` (Windows) | `if *VERBOSE` @1120 | `D` |
| 12 | 1216 | `Found existing git repository at {checkout_dir:?}` | `if *VERBOSE` @1215 | `D` |

#### `src/resolver.rs` — 6 (all unguarded solver chatter — the noisiest offender)

| # | Line | Statement (abridged) | Guard | Target |
|---|------|----------------------|-------|--------|
| 1 | 64 | `Unable to get dependencies for {} version {version}. This version cannot be chosen:\n\t{e}` | none | `D` |
| 2 | 101 | `Unable to update dependency database for {}: {e}. This version cannot be chosen:` | none | `W` |
| 3 | 125 | `Unable to resolve version range for package {} version {version}. This version cannot be chosen:` | none | `D` |
| 4 | 179 | `Choosing version for package: {}, range: {range}` | none | `T` |
| 5 | 202 | `Package: {}, version: {v}` | none | `T` |
| 6 | 203 | `No available versions for package {}` | none | `W` |

#### `src/dependency.rs` — 2 (both inside `#[cfg(test)]` fns)

| # | Line | Statement | Target |
|---|------|-----------|--------|
| 1 | 132 | `println!("{dep_spec}")` (Display coverage) | `D` |
| 2 | 149 | `println!("Testing: {dep_spec}")` | `D` |

#### `src/third_party/semver_pubgrub/mod.rs` — 6 (vendored, 3 pairs)

| Lines | Statement | Target |
|-------|-----------|--------|
| 594 / 595 | `eprintln!("{}", ver)` / `eprintln!("{}", req)` | `T` |
| 636 / 637 | same pair | `T` |
| 689 / 690 | same pair | `T` |

Vendored code stays otherwise untouched (no logic changes).

### B. `VERBOSE` guard sites — 12 (+1 definition, +1 import)

- Definition: `src/lib.rs:56` `pub static VERBOSE: Lazy<bool>`
- Import: `src/git.rs:2` `use crate::{PROGRESS, VERBOSE};`
- Guards: `src/git.rs` @ 339, 352, 444, 449, 1026, 1032, 1084, 1111, 1120, 1215 (10) · `src/lib.rs` @ 109, 214 (2)

### C. `prodash` progress sites

**Infrastructure (`src/lib.rs`)**

| Line | Item |
|------|------|
| 11 | `use once_cell::sync::Lazy;` |
| 20 | `use prodash::tree::Root;` |
| 26 | `static PROGRESS: Lazy<Arc<Root>>` — `message_buffer_capacity: 200` |
| 34 | `const DEFAULT_FRAME_RATE: f32 = 6.0` |
| 36 | `fn setup_line_renderer_range(progress, levels)` — `level_filter`, `frames_per_second`, `initial_delay: 1000ms`, `timestamp: true`, `throughput: true`, `hide_cursor: true`, `StreamKind::Stderr` |
| 71 / 183 | renderer created in `sync_dependencies()` / `install_dependencies()` with `progress_range = 1..=4` |
| 135 / 221 | `handle.shutdown_and_wait()` — any `?`-induced early return between renderer creation (71 / 183) and these calls leaks a live renderer (e.g. `parse_dependencies_yaml_file(...)?` @197, `resolve(...)?` @207, `lockfile.to_file(...)?` @263) |

**`src/git.rs` item call sites, by function**

| Function (sig line) | Progress sites | Notes |
|---------------------|----------------|-------|
| imports @5,6 | `gix::progress::prodash::Progress`, `…::tree::Item` | adapter must re-export these |
| `clone_dependency_database` @441 | 463 `add_child("Fetching …")`, 465 `add_child("")`, 474 `drop`, 479 `done`, 485 `fail`, 490 `drop`, 502 `add_child("Cloning dependency database for …")`, 508 `init(Some(1))`, 511 `add_child`, 518 `inc`, 523 `done`, 529 `fail` | 12 |
| `fetch_tag_from_db` @545 | 581 `add_child`, 599 `done`, 607 `fail` | takes `&mut Item` param |
| `fetch_ref_from_db` @616 | 657 `add_child`, 675 `done`, 683 `fail` | takes `&mut Item` param |
| `checkout_or_clone_object_from_database` @692 | 695 `progress: &mut Item` param | plumbing only |
| `clone_with_object_from_database` @706 | 709 param, 770 `add_child`, 774 `init(Some(2))`, 776 `add_child`, 786 `drop`, 788 `inc`, 800 `inc`, 804 `info`, 810 `info("  - {}")`, 824 `done`, 831 `fail`, 839 `drop` | 12 |
| `checkout_object_from_database` @855 | 858 param, 880 `add_child`, 889 `info`, 895 `info`, 898 `info("updating submodules")`, 924 `done`, 925 `drop`, 956 `add_child_with_id(CheckoutFiles)`, 960 `add_child_with_id(BytesWritten)`, 965 `init(count files)`, 966 `init(bytes)`, 987 `done`, 992 `drop` | 13 |
| worktree remove/fix-permissions block @~1013 | 1013 `add_child_with_id`, 1025/1031 `inc`, 1039 `done`, 1041 `step()`, 1045 `add_child_with_id`, 1091/1116/1125 `inc`, 1131 `done`, 1133 `step()` | 11 |
| submodule info block @1157 | 1157 `add_child_with_id`, 1165 `info`, 1171 `info` | 3 |
| `checkout_from_database` @1188 | 1195 `&PROGRESS`, 1206 `add_child`, 1225 `done`, 1229 `drop`, 1276 `done`, 1282 `fail`, 1334 `init(Some(3))`, 1336 `add_child`, 1345 `drop`, 1350 `add_child`, 1356 `drop`, 1358 `inc`, 1393 `done`, 1399 `fail`, 1408 `inc`, 1412 `done`, 1417 `drop` | 17 |
| `update_submodules` @1504 | 1505 `progress.map(… add_child)`, 1527 `done`, 1535 `fail` | 3 |
| **`src/lib.rs`** `sync_dependencies` | 116 `PROGRESS.add_child`, 123 `done("Complete")`, 127 `fail("Failed:\n\t{e:?}")` | 3 |

Total: **68** item calls + **6** `&mut Item`/`Option<&mut Item>` plumbing params (git.rs 545, 619, 695, 709, 858, 1504) + **10** explicit `drop(...)` calls — the single biggest source of "ugly".

### D. Dependencies (`Cargo.toml`)

- `prodash = "^30.0.1"` features: `render-line`, `render-line-crossterm`, `render-line-autoconfigure`, `progress-tree`, `progress-tree-log`, `local-time`, `signal-hook`
  - Verify-then-drop: `progress-tree-log`, `local-time`, `signal-hook` (interrupt handling comes from `gix::interrupt::IS_INTERRUPTED`, not prodash's hook)
- `gix = "^0.74.0"` features: `blocking-http-transport-reqwest-rust-tls`, `progress-tree` — **keep** `progress-tree`
- `once_cell = "^1.21"` — still needed for `PROGRESS`-equivalent global (or move to `std::once`/`std::lazy` + a `Mutex`-free init)
- To add: `log`, `log-level`, `ansi` (colour + TTY detect; crossterm already in-tree via prodash)

### E. Tests

- `tests/common/mod.rs` — library-API only, asserts on git state, **never on stdout** → logging changes are stdout-safe
- `tests/test_lockfile.rs`, `tests/update/test_update.rs`, `tests/sync/test_sync.rs`, `tests/clean/test_clean.rs` — registered in `Cargo.toml` `[[test]]` blocks; they call lib fns directly ⇒ `init()` must tolerate being called twice / from a non-TTY context
- `src/dependency.rs` has in-file `#[cfg(test)]` tests that print (Inventory A/`src/dependency.rs` rows) — route to `log::debug!`

---

## 2. Crate stack (decision, recorded here)

**Registry verification (crates.io API, done before any code change):**

| Candidate | Verdict |
|---|---|
| `log-level` | **does not exist** on crates.io — the crate named in the original plan is unavailable |
| `loglevel` (0.4.0) | exists, but `apply()`/`apply_custom()` force **`env_logger` as the backend**, which would own the output format and defeat the rich-backend requirement → rejected |
| `pretty-log`, `fancy-log` | exist, but own the format; no phase/summary awareness → rejected |
| `log` (resolves to **0.4.34**) | **chosen**: facade + macros; backend implemented by us |
| `crossterm` (**0.28.1**) | **chosen** for TTY detection only (`crossterm::tty::IsTty`); colour emitted as raw ANSI constants |

Backend contract verified against vendored `log-0.4.34`: implement `log::Log` with
`enabled(&Metadata)`, `log(&Record)`, `flush()`; read `record.level()` and `record.args()`
(`record.args()` formats with `{}`); install via `set_logger(&LOGGER)` + `set_max_level(filter)`.

**Final stack:** `log` (facade + our backend) · `crossterm` (TTY detect) · `prodash` (progress only,
features trimmed to `render-line`, `render-line-crossterm`, `render-line-autoconfigure`,
`progress-tree` — `progress-tree-log`, `local-time`, `signal-hook` are unused by our code; interrupt
handling comes from `gix::interrupt::IS_INTERRUPTED`).

**Deviation from the original plan:** level parsing is hand-rolled (~40 lines, §3) because no
published crate parses levels without also owning the backend.

**Chosen answers to the open questions:** (1) stack above, not `clack` (interactive-oriented, fights
the rayon-parallel phase model); (2) one single-line bar per package in parallel phases, one
aggregate bar per sequential phase, nested sub-bars not rendered (level filter `1..=1`); (3) emoji
removed — ASCII glyphs `ok`/`~`/`xx`/`#` with colour, plain text under `--plain`; (4) `-v` is
**countable**: default `warn`, `-v` `info`, `-vv` `debug`, `-vvv`+ `trace`, `-q` `error`.

## 3. `src/logging.rs` — new module (final API)

```rust
pub enum ColorMode { Auto, Always, Never }
pub struct InitOptions { verbosity: u8, quiet: bool, color: ColorMode, plain: bool, log_level: Option<String> }

pub fn init(options: InitOptions)                                  // idempotent; installs backend, sets level + style flags
pub fn resolve_level(options: InitOptions) -> LevelFilter          // policy below
pub fn current_level() -> LevelFilter                              // log::get_max_level()
pub fn parse_level_name(value: String) -> Option<LevelFilter>      // off|none|quiet|error|err|warn|warning|info|debug|trace|all
pub fn parse_rust_log(spec: String) -> Option<LevelFilter>         // `mod=level` or bare, comma separated, max wins

pub fn sym_ok() / sym_warn() / sym_fail() / sym_dirty() / sym_lock() -> String   // styled, ASCII-only
pub fn error_text(err: &anyhow::Error) -> String                   // message + '\n'-joined cause chain

pub struct SummaryRow { name, version, tag, commit, status: String }
pub fn render_summary(title: String, rows: Vec<SummaryRow>)        // stdout, ANSI-aware column alignment
```

Level policy (order matters): (1) `--log-level` wins; (2) else `RUST_LOG` when `verbosity == 0 && !quiet`;
(3) else `-q` → `LevelFilter::Error`; (4) else flag count `0`→`Warn`, `1`→`Info`, `2`→`Debug`, `>=3`→`Trace`.

Backend formatting rules: records go to **stderr**; `HH:MM:SS` prefix only when level >= `Debug`;
level tag padded to 5 chars (`error:`, `warn :`, `info :`, `debug:`, `trace:`) coloured red/yellow/dim/grey/grey;
message first line after the tag, continuation lines indented 7 spaces (replaces the `"\n\t{e}"` idiom);
the summary table goes to **stdout** and is never level-filtered.

## 4. `src/progress.rs` — prodash adapter (final API)

```rust
pub type Item = gix::progress::prodash::tree::Item;   // only module allowed to name prodash

pub struct ProgressHandle { join: Option<prodash::render::line::JoinHandle> }
impl Drop { shutdown_and_wait() }                     // RAII: fixes the ?-path leaks

pub fn start() -> ProgressHandle                      // no-op (None) under --no-progress / non-TTY
pub fn root() -> Arc<Root>                            // replaces lib.rs PROGRESS
pub fn with_progress(label: String, total: Option<u32>, body: Fn(&mut Item) -> anyhow::Result<T>) -> anyhow::Result<T>
pub fn gix_progress(label: String) -> Item            // scoped child for gix fetch/checkout calls
pub fn note(label: String, message: String)           // one-shot info line inside the progress tree
```

`with_progress` owns `add_child` -> `init(total)` -> run -> `done`/`fail` -> `drop`, so the 10 explicit
`drop(...)` calls and the paired `done`/`fail` blocks disappear from `src/git.rs`.

Renderer options for "minimal bars": no timestamp, no throughput, no hide-cursor, `frames_per_second = 10`,
`initial_delay = 0`, level filter `1..=1` (top-level items only), message truncated to terminal width.
Non-TTY fallback: bars suppressed, phase start/finish emitted as `log::info!` lines.

## 5. Remove the `VERBOSE` hack

- Delete `src/lib.rs:56` `pub static VERBOSE: Lazy<bool>` (the `env::args()` re-scan) and the `use crate::{PROGRESS, VERBOSE}` import at `src/git.rs:2`
- The 12 guards (`git.rs` 339, 352, 444, 449, 1026, 1032, 1084, 1111, 1120, 1215 · `lib.rs` 109, 214) lose their `if *VERBOSE` wrapper: the body becomes a bare `log::debug!`/`log::trace!` call, and the `else if *VERBOSE` at `git.rs:352` becomes a bare `else { trace!(...) }`
- `once_cell` stays in `Cargo.toml` only while `progress.rs` needs a lazy global root; drop the dep if the root becomes a plain `static`

## 6. Print-site sweep (exact mapping)

Legend: `E`=`log::error!` `W`=`log::warn!` `I`=`log::info!` `D`=`log::debug!` `T`=`log::trace!` `SUM`/`FOOT`=handled by `render_summary` (step 7)

| File | Site → level | Notes |
|---|---|---|
| `lib.rs` | 110→`D` · 150→`E` (use `error_text(e)`) · 172→`I` · 215→`D` · 158, 286→`FOOT` · 287→`I` · 139, 144, 146, 230, 234, 240→`SUM` | `SUM` rows move into `SummaryRow` structs, not log calls |
| `git.rs` | 340, 353→`T` · 445, 450→`D` · 564, 639→`W` (drop the literal `Warning: ` prefix, the tag carries it) · 1027, 1033→`T` · 1087, 1112, 1121→`D` · 1216→`D` | |
| `resolver.rs` | 64, 125→`D` · 101→`W` · 179, 202, 203→`T` | 203 (`No available versions`) is the only solver line worth seeing at `warn`; keep it `W` |
| `dependency.rs` | 132, 149→`D` | both inside `#[cfg(test)]` fns |
| `third_party/semver_pubgrub` | 594/595, 636/637, 689/690→`T` | collapse each pair into one `trace!("version {} vs requirement {}", ver, req)` |

Incidental fixes landed with the sweep: `anyhow::anyhow!(format!(…))` (`lib.rs:90`) → `anyhow::anyhow!(…)`; `unwrap_or("invalid".to_string())` → `unwrap_or("invalid")`; the `"…:\n\t{e}"` message shapes → plain messages (the backend indents continuations).

## 7. Phases + summary table

Phase banners are `log::info!` lines (`info : resolving dependencies`), so they vanish under `-q` while the table stays on stdout.

```rust
struct SummaryRow { name, version, tag, commit, status }   // status: "ok" | "ok (dirty)" | "failed"

render_summary("gipm update — 5 packages", rows)
// package  version  tag        commit    status
// zlib     1.2.13   v1.2.13    9a2b3c4   ok
// openssl  3.4      openssl_3_4 8f21c07  ok (dirty)
// curl     7.88     curl-7.88  1d4e7a2  failed
```

- `sync_dependencies()`: rows from `checkout_results` (name, commit, ok/ok (dirty)/failed) — replaces `lib.rs:139-158`
- `install_dependencies()`: rows from `resolved_dependencies` (name, version, tag, commit) — replaces `lib.rs:230-240`
- footer line (`FOOT`) becomes one `log::info!` with `sym_ok()`/`sym_lock()`; failures still `log::error!` per package plus the returned `anyhow` error

## 8. CLI surface (`src/main.rs`)

```rust
#[arg(short, long, action = clap::ArgAction::Count)] verbosity: u8
#[arg(short, long, default_value_t = false)] quiet: bool
#[arg(long)] log_level: Option<String>
#[arg(long, default_value_t = false)] plain: bool
#[arg(long, default_value_t = false)] no_progress: bool
#[arg(long, value_enum, default_value = ColorMode::Auto)] color: ColorMode
```

`main()` order: parse args → `logging::init(InitOptions { … })` → `let progress = progress::start()` (RAII) → `match cmd` → on `Err`, `log::error!("{}", logging::error_text(e))` and return the exit code, so anyhow's `Error: ` dump never reaches the terminal.

## 9. Parallel progress + renderer lifetime

- `sync_dependencies()` and `install_dependencies()` keep one `with_progress(name, …)` per package inside the existing `par_iter().map()` bodies (`lib.rs:64`, `lib.rs:214`); no nested children are rendered (level filter `1..=1`)
- `ProgressHandle` is created once per command in `main()` and dropped at scope exit, which calls `shutdown_and_wait()` — this replaces the two manual `handle.shutdown_and_wait()` calls (`lib.rs:135`, `lib.rs:221`) and closes the leak on the `?`/`bail` paths (`lib.rs:197`, `lib.rs:207`, `lib.rs:226`, `lib.rs:263`)
- `progress::root()` returns the shared `Arc<Root>`; `git.rs` never names `prodash::*`

## 10. Tests

Unit tests in `src/logging.rs`:
- `test_level_resolution` — flag counts 0/1/2/3, `-q`, `--log-level`, `RUST_LOG` precedence
- `test_parse_level_name` / `test_parse_rust_log` — aliases, `mod=level`, garbage input → `None`
- `test_visible_width` — ANSI-styled strings measure as unstyled width
- `test_render_summary_alignment` — wide/unicode names keep columns aligned (capture into a string, not stdout)
- `test_init_is_idempotent` — calling `init()` twice does not error (protects `tests/**` which call the lib API)

Integration tests (`test_lockfile`, `test_update`, `test_sync`, `test_clean`) assert on git state only, so they must stay green unchanged — they are the regression signal for step (c).

## 11. Verification commands

```
cargo build --quiet
cargo test --test test_lockfile --test test_update --test test_sync --test test_clean
cargo test logging
gipm update            # default: bars + warn-level log + summary table
gipm update -vv        # timestamps + per-package decisions
gipm sync -q           # errors only, no log lines, table still on stdout
gipm clean
RUST_LOG=trace gipm update -v --no-progress --plain
```

Windows console check (this repo's dev host): run the above in `cmd.exe` and PowerShell with `--plain` (no ANSI, no emoji) and without (colour + bars); confirm no mojibake and no cursor artefacts.

## 12. Docs

- `README.md` "Use": list `-v/-vv/-vvv`, `-q`, `--log-level`, `--plain`, `--no-progress`, `--color`, and `RUST_LOG`
- `CLAUDE.md` architecture: add `src/logging.rs` (the `log` backend + level policy + summary renderer) and `src/progress.rs` (prodash adapter); state the rule **prodash is an implementation detail for gix progress only — never name it outside `src/progress.rs`**
- `todo.md`: add `--machine-readable` (JSON) output mode as deferred work

## 13. Landing order (lowest risk first)

1. (a) `Cargo.toml` deps + `src/logging.rs` + `init()` wired into `main.rs` → build green
2. (b) print sweep (step 6) → **run the four integration tests before continuing**
3. (c) `src/progress.rs` adapter + prodash feature trim + `git.rs` plumbing rewrite → re-run integration tests
4. (d) summary table + CLI flags (steps 7, 8)
5. (e) docs (step 12)

## Risks / watch-list

- (c) is the only step that can break real git behaviour — keep gix call signatures untouched until the adapter is verified against `tests/update/test_update.rs`
- prodash item `drop()` discipline (10 explicit `drop(...)` calls today) and renderer shutdown on `?` paths: the `with_progress` helper and `ProgressHandle::Drop` must own both
- Level precedence (`--log-level` > `RUST_LOG` > `-q`/`-v` count) must stay deterministic and be documented in both the module header and `README.md`
- Windows console: no emoji, no ANSI under `--plain`, `--color never` must not emit escapes to redirected output
- `render_summary` writes to stdout while records go to stderr — do not route the table through `log::*` or `-q` will swallow it

---

## 14. Follow-up: the bars themselves (indicatif)

The first pass kept prodash's *line renderer*, which was the thing the user actually
complained about: it repaints with its own cursor bookkeeping, so log lines written
straight to `stderr` fight over the cursor and the terminal jumps around. The renderer
was replaced, the data model was not.

- **`prodash` stays** (gix callbacks require it) but its features are trimmed to
  `progress-tree` only — no `render-line*` at all.
- **`indicatif` (0.18) + `console` (0.16)** do the drawing. `indicatif` is the usual
  answer to "rich-style progress in a Rust CLI"; `console` is already an indicatif
  dependency, so it is added explicitly for colour control and terminal probing.
- `indicatif`'s `in_memory` feature is enabled so `progress::test_progress_frame` can
  assert on a rendered frame (`InMemoryTerm`) instead of eyeballing a TTY.

Layout (matches the "overall bar + one bar per package" decision):

```
             total ━━━━━━━━━━━━━━━╌                 50% 0s 1 of 2 packages
              zlib ━━━━━━━━━━━━╌                    40% 0s
              curl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0s fetched
```

- One `MultiProgress`, one render thread, one owner of the `stderr` cursor.
- Level-1 prodash items become bars; level-2+ items are folded into their parent
  (`Key::shares_parent_with(&parent_key, 1)`), summing `step`/`done_at`.
- `Message`s from `done()`/`fail()`/`info()` become the bar's status text; a non-`Info`
  message marks the task done (full green bar).
- Log lines never touch `stderr` directly while bars are alive: `logging.rs` calls
  `progress::write_line`, which queues into `PENDING` and the render thread prints it
  through `MultiProgress::println` **above** the bar block. That is the fix for the
  jumping cursor.
- `bar_style()` uses `━╌ ` everywhere — there is no ASCII fallback. The Windows console
  renders those glyphs fine on UTF-8 codepages, and `--plain` (which draws no bars at all)
  is the escape hatch for legacy codepages. `console::set_colors_enabled_stderr` is
  synced from `logging::init` so `--plain`/`--color never` kill bar colour too.
- `--plain` disables bars entirely (no cursor control at all), `--no-progress` keeps
  items alive for gix but draws nothing.
- Level-1 item names were shortened (`git.rs`, `lib.rs`) to fit the 22-column prefix —
  `"Fetching zlib in C:\Users\…"` became `"Fetching zlib"`, and the checkout phase
  labels bars with the bare package name.

Follow-up polish (spinners, smoothness, the 100%-backwards jump):

- Unknown-total tasks now get a **braille spinner** (`⠋⠙⠹…`) instead of an empty track.
  Note the template syntax gotcha: `{spinner.cyan}` parses `spinner.cyan` as the *key*
  (only `:` separates key from width/style), so it silently renders nothing — the
  working form is `{spinner:1.cyan}`.
- Bars are no longer ASCII-only: `━╌ ` everywhere, and the bar width is fitted to the
  terminal (`width - prefix - trail`, clamped to `MIN_BAR_WIDTH`..`MAX_BAR_WIDTH` = 8..100)
  rather than being fixed. `--plain` remains the escape hatch for legacy codepages (it draws no bars).
- **The jump from 100% backwards** had two causes, both fixed:
  1. bars were addressed by *position* in the snapshot, so when a sibling finished and
     the tree shrank, every later task slid onto the previous task's bar;
  2. the overall bar's length was "tasks alive right now", which grows as new tasks
     appear after an all-done frame.
  Bars are now keyed by the prodash `Key` (`Vec<(Key, ProgressBar, BarSpec, length)>`),
  tasks that vanish unfinished have their bar removed, and both the overall counters
  (`total_seen`/`done_seen`) and each task's track length are monotonic high-water marks.
- Stage clarity: level-2 item names are folded into the parent bar as a `stage` label
  shown as the bar message when the task has no explicit status message
  (`zlib … 40% 0s fetch`).
- `cargo clippy` is now **clean (0 warnings)**: `--fix` handled the mechanical ones
  (`needless_return`, `redundant_field_names`, `collapsible_if`, …), the remaining
  `needless_range_loop`/`manual_clamp` hits in `progress.rs` were rewritten by hand,
  and the one pre-existing `permissions_set_readonly_false` in `git.rs` keeps its
  behaviour with a targeted `#[allow]` plus a comment (changing it would alter
  checkout semantics on Windows).

Second follow-up (overall spinner, the duplicate "total" line):

- **Two "total" bars** was not two phases: it was `ProgressBar::enable_steady_tick`.
  A steady tick installs a `Ticker` that spawns its **own thread** redrawing that one
  bar through its own draw target — inside a `MultiProgress` that prints a stray
  standalone copy of the line (and churns the cursor). Every bar had a steady tick,
  so the overall line appeared twice. Fix: no per-bar tickers at all; the render
  thread drives everything (`draw()` calls `tick()` on the overall bar and on
  spinner bars).
- The overall bar got its own style (`overall_style`) with a leading braille spinner,
  so there is always motion during a phase:
  `total ⠹ ━━━━━━━━━╌ 33% 0s 1 of 3 packages`.

Third follow-up (the result table):

- `format_summary` now draws a boxed table: bold title, dim rules, bold header,
  `┌┬┐ ├┼┤ └┴┘ │` (ASCII `+ | -` under `--plain` / redirected output).
- `visible_width` ignores ANSI escapes, so the coloured status column no longer
  pushes the right border out of line (the old `chars().count()` padding did).
- Styled output fits the table to the terminal width by shrinking the widest
  columns and marking cuts with `…` (`..` in ASCII); `--plain`/piped output stays
  lossless so redirected reports keep full commit shas.

Fourth follow-up (submodule progress, honest counters, colour, shas):

- **"0 of 1" on the overall bar.** The prodash tree only ever holds work that is
  *currently* running — an `Item` is removed from the tree as soon as it goes out of
  scope — so `bars.len()` can never be the denominator. `progress::start(expected)`
  and `progress::set_expected(n)` hand the real phase size to the renderer (known
  before the phase for `sync`, known after the solve for `update`), and
  `progress::task_done(name)` counts finished packages by name (deduped). The overall
  bar now reads `1 of 6 packages` while three packages are still fetching.
- **Submodule progress.** `update_submodules` used to run `git submodule update` with
  inherited stdio: a silent stretch of the run with no bar at all. It now
  - creates a dedicated item — nested `submodules` under the package bar when a
    parent exists, its own `{name} submodules` line otherwise,
  - `init(count)` with the submodule count so the bar has a real total,
  - drains the child's stdout and stderr alternately in 4 KiB chunks (draining one pipe
    to EOF first lets the child fill the other buffer and block behind `wait()`), and
    advances the counter on every complete `From <url>` line — the trailing partial line
    is carried into the next chunk so a line straddling a read boundary is counted once,
  - clamps the counter to the requested submodule count and reports the real fetched count
    in the `done()` message,
  - logs the captured stdout/stderr once at `debug!` (visible from `-vv` up), and the
    failure reason at `warn!` so a piped run does not lose it (the bar's `fail()` message
    is only drawn when bars are alive).
- **Item naming is package-first** so bars sort and read as one group:
  `zlib db fetch`, `zlib db clone`, `curl` (checkout), `openssl submodules` — the `db`
  phases are named after their package so they group with it, and they are not counted as
  packages by `task_done`, so they never inflate the overall bar's numerator.
- **Colour everywhere, one palette.** Bars: bold names, cyan running track, green
  when done, dim stage text, cyan overall message. Table: bold package, cyan
  version, grey tag/sha, green or yellow status. Log lines keep their coloured level
  tag. `--plain` and redirected output stay ANSI-free.
  Template gotcha: `{msg.cyan}` is parsed as the *key* `msg.cyan` (only `:` separates
  key from width/style) and renders nothing — the working form is `{msg:.cyan}`.
- **The table gained the resolved sha.** `install_dependencies` fills the `commit`
  column with `get_commit_hash_for_version(version)`, so a report shows tag *and* the
  commit it points at; `sync_dependencies` shows the pinned commit and drops the
  semver/tag columns since sync carries neither (empty columns are dropped rather
  than drawn as gutters).


## Deviations and late corrections

Found while implementing the plan; each supersedes the section above it.

- **The renderer is tty-gated.** The plan assumed `MultiProgress::println` was a safe
  home for log lines while bars were "enabled". indicatif demotes a non-terminal draw
  target to `none()`, which drops *every* `println` too — so a piped/CI run that thought
  it had bars lost all of its log output. `progress::drawing()` (`enabled()` *and*
  `stderr` is a tty) is the gate now; `enabled()` alone is only ever used for the gix
  callbacks, which still need the prodash tree.
- **`result()` is not a log level.** The plan's default of `warn` hid "what the command
  just did" (lockfile path, `clean`'s result, the success footer). Raising the default to
  `info` was the obvious fix, but pubgrub logs its own reasoning at `info!` and flooded
  the default run. The default stays `warn`; those user-facing lines go through
  `logging::result()`, which prints regardless of level and is silenced by `-q`/`--log-level off`.
- **Solver failures are `warn!`, not `debug!`** (plan inventory rows 66, 102, 125): an
  unreachable dependency or an unsolvable graph has to be visible in a default run, and
  `resolve()` now carries a `context()` so the error says which ranges were involved.
- **`ProgressHandle` is a real `impl Drop`**, so the `?` paths stop the renderer and flush
  queued lines; the `JoinHandle` is deliberately detached (a type with a user-defined
  `Drop` cannot have its fields moved out), which is why shutdown waits on the
  `RENDER_EXITED` flag rather than `join()`ing.
- **The render thread caches `stderr`'s tty-ness.** The Windows implementation of the check
  costs several console API calls, and a hot log path calling it per line roughly doubled
  a warm `gipm sync` (628 ms -> 1269 ms). `stderr_is_tty` resolves once.
- **Table column visibility is decided from the raw row fields, not the styled cells**
  (`!cells[i].is_empty()` was always true under `--color always` because an empty styled
  cell still carries the escape pair). See `logging::keep_columns`.
- **Truncation closes the open style** before the ellipsis, otherwise a cut cell bleeds
  colour into the table borders; and the ellipsis is `…` only when the output is styled
  (`..` otherwise), which is the opposite of the original comment.
