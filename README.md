# `gipm`

`gipm` - Simple **Gi**t **P**ackage(like) **M**anager

## Installation

Not on crates.io yet, so there is nothing to `cargo install` from the registry; build it from
this repository instead:

```sh
git clone https://github.com/<you>/gipm.git
cd gipm
cargo build --release          # -> target/release/gipm(.exe) on Windows
cargo install --path .         # once the package is published, `cargo install gipm` works
```

## Use

- `gipm update` - resolves and checks out packages
- `gipm sync` - sync the `.gitvenv` checkouts to the `gipm.lock` versions
- `gipm clean` - remove `.gitvenv`
- `gipm --help` - show help

### Output control

Logs go to `stderr`, the result summary goes to `stdout`, so `gipm update 2>/dev/null` gives
you just the table. Progress bars are one line per package (plus an overall bar with a
spinner) and are only drawn on a terminal; the summary table also shows the commit sha each
resolved tag points at.

- `-v` / `--verbose` (countable): `-v` info, `-vv` debug, `-vvv` trace (default is warn)
- `-q` / `--quiet`: only report errors, also suppresses progress bars
- `--log-level <level>`: explicit level (`off`, `error`, `warn`, `info`, `debug`, `trace`), wins over `-v`
- `RUST_LOG` is honoured when no verbosity flags are given
- `--color <auto|always|never>`: colour policy (default: colour only on a terminal)
- `--plain`: strip colour and cursor control, and draw no bars at all (safe for `cmd.exe`, log files, CI)
- `--no-progress`: suppress progress bars (logs and the summary are still printed)

## How does `gipm` work?

- ⚡ designed for speed - `gipm` is written in rust, and uses the same [pubgrub](https://github.com/pubgrub-rs/pubgrub) dependency resolution library as [`uv`](https://docs.astral.sh/uv/)
- ✅ designed for flexibility - `gipm` utilizes semantic version ranges, improving flexibility over submodule limitations
- 🔒 designed for repeatability - `gipm` provides a .lock file to guarantee repeatability when necessary
- 🧠 designed for portability - `gipm` utilizes the [`gix`](https://github.com/GitoxideLabs/gitoxide) library to drive its git interactions; no need to manage any external tooling.
  - Note: submodules are read from the parent's index (`gix::Repository::submodules()`) and cloned
    through the same object-clone path as their parent, so a submodule's progress arrives in gix's
    tree rather than being scraped from a child process. Nested submodules are handled by the same
    recursion; there is no shelled-out `git` anywhere in the tool.

`gipm` works by reading in a `dependencies.yaml` file, with the following format:

```yaml
dependencies:
  - version: "~3"
    url: https://gitlab.com/libeigen/eigen.git
  - version: "^7.88"
    url: https://github.com/curl/curl.git
    prefix: curl-
    replacement:
      - ["_", "."]
  - version: 1.2.13
    url: https://github.com/madler/zlib.git
  - version: ~3.4
    url: https://github.com/openssl/openssl.git
    prefix: openssl-
  - version: "~0.4"
    url: https://github.com/gipm-rs/test-repo-1.git
```

`gipm` will recursively solve the dependency problem by considering further `dependency.yaml` files at each of these repositories and versions. `gix` facilitates an efficient in-process extraction of the yaml file without any extra overhead of needing to to a tree checkout for this resolution process.

`gipm` aims to efficiently store git repositories for efficient clone speed and checkout speeds. `gipm` clones dependency databases in `~/.gipm/db`, storing refs for use across many `gipm` workspaces.

Once the dependency problem is solved, `gipm` will clone or update a shallow repository under .gitvenv for the resolved dependencies, and then re-point the remote to the original url. This facilitates efficient checkout processes, and re-use for shared dependencies, while still allowing flexibility to develop against dependencies in your resolved workspace.

## Who is this for?

This is designed for:

- Teams that have nested dependencies, but don't have a good way to manage packages, or may not publish packages
- Systems that may not have a good way to publish packages, potentially internal tooling limitations
- Systems where submodules are currently over-utilized, and may have conflicting nested requirements
- Langauges without strong package management systems:
  - C/C++
  - Fortran
  - MATLAB
  - etc
- Users that want to use submodules, but want the flexibility of a semantic version range

## Why shouldn't I just use submodules?

If your dependencies do not have further dependencies of their own, submodules work great, and you should use them. However, when muti-layered dependency trees exist these become a nightmare to manage with git submodules. Having a package-like system tagging along with git makes sense. With the modern semantic versioning guidelines we can resolve a compatible package for use across all of your dependencies.

## What isn't this trying to do?

This is not a replacement for uv, cargo, npm, etc. If you are working within a given language with a well supported package manager, you should stop here and use that to manage those dependencies.

## dependencies.yaml format

The dependencies.yaml file currently has one supported tag: `dependencies:`:

```yaml
dependencies: # REQUIRED
  - version: "<semantic-version-range>" # REQUIRED
    url: <path/to/git/repo> # REQUIRED
    prefix: <prefix> # OPTIONAL
    replacement: # OPTIONAL
      - [<from>, <to>] # OPTIONAL
      - ["_", "."] # example of replacement
  - version: "version"
    ...
```

### dependencies

This is the top level entry for defining dependencies. In the future there may be more top level tags, i.e. to set git options potentially. Dependencies contains an array of at versions, urls, with some optional extras to help with resolving tags.

### version

This is the semantic version specification. This should follow the [cargo version requirement syntax](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#version-requirement-syntax)

- TODO: in the future, a generic ref may be allowed here (i.e. branch, sha) for an exact match. Currently, the ref must be a semantic version specification, or an exact tag

### url

This is the path to the repository. This can be specified in any compliant git path (i.e. ssh, https, etc) - but the protocol must be supported on the system with appropriate keys/etc.

- TODO: Some additional testing surrounding cases where users don't have those configured should be done.

### prefix

For most repositories, `gipm` can automatically infer a prefix to a semantic version, if that semantic version is consistent and repeated across >= 75% of tags that look to be semantic in nature. For cases where `gipm` cannot automatically infer the desired prefix to the semantic-like sequence, the prefix may be explicitly set.

### replacement

For most repositories, `gipm` can automatically infer common replacements for semantic version matching with tags. Most commonly this may be `-`, or `_`. However, if this cannot be automatically inferred, it can be explicitly specified here. Note that a semantic version is in the form `major.minor.patch` for release versions.

## Testing

The suite is hermetic: every target builds its own fixture repositories (tiny bare repos reached
over `file://`) and points `HOME` at a per-target cache, so no test reads or writes `~/.gipm/db`
and none needs network — except `test_network`, which is opt-in and skips when `GIPM_NETWORK` is
unset.

```sh
cargo test --all-features              # all targets
cargo test --test test_update          # one target: test_lockfile | test_update | test_sync | test_clean
                                       #   test_submodule | test_branches | test_failure | test_cache
                                       #   test_cli | test_drift | test_manifest | test_broken | test_upstream
                                       #   test_network (needs GIPM_NETWORK=1)
cargo llvm-cov --all-features --workspace --ignore-filename-regex='tests/|third_party/'
```

What each new target pins down:

- `test_submodule` - a three-level nested submodule chain; each level is pinned to the commit its
  parent recorded, not to the child's `HEAD`, and the lockfile stays flat (one package).
- `test_branches` - a fixture whose default branch is `trunk`, not `main`.
- `test_failure` - bad url, unsatisfiable range, malformed version string, malformed manifest,
  `sync` with no lockfile; nothing is half-written.
- `test_cache` - a cached database that opens but holds no objects is treated as absent and re-cloned.
- `test_cli` - the flag surface, and that stdout carries only the summary table.
- `test_drift` - re-resolving an existing checkout to a different tag moves `HEAD`, the tag ref and
  the worktree in both directions.
- `test_manifest` - a committed manifest replayed through `sync`/`update`/`clean`.
- `test_broken` - a lockfile entry that cannot be honoured fails, is reported, and leaves the rest
  of the table intact.
- `test_upstream` - upstream grew a new tag after the initial resolution; the checkout fetches it.
- `test_network` - the only target that reaches a live remote, and it is opt-in: without
  `GIPM_NETWORK=1` it says so and passes. When on it resolves `test-repo-1` over https, replays a
  warm update against the databases it just downloaded, fails a repository the server refuses to
  serve, and runs the CLI under a pty — the only way the progress renderer draws at all.

## Limitations

- This tool requires dependencies follow [semantic versioning](https://semver.org/) practices on their git repositories, and manage a **consistent tag format** that represents each release. This is best practice and generally adhered to across most repositories.
- Dependencies with git submodules may define the system in such a way that multiple copies of a dependency exists in your workspace (i.e. one copy in .gitvenv, and one as a submodule of a dependency). There is no way around this currently.
- Beware of pitfalls with yaml specifications - [the yaml document from hell](https://ruudvanasseldonk.com/2023/01/11/the-yaml-document-from-hell) is a good read
  - Note: YAML may be rethunk here in the future, but it is nice for its ease of reading for the user.
