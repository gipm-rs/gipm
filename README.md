# `gipm`

`gipm` - Simple **Gi**t **P**ackage(like) **M**anager

## Installation

- `cargo install gipm`

## Use

- `gipm update` - updates packages
- `gipm sync` - sync to lockfile versions
- `gipm clean` - remove .gitvenv
- `gipm --help` - show help
- all commands can be run verbose with `-v|--verbose`.

## How does `gipm` work?

- ⚡ designed for speed - `gipm` is written in rust, and uses the same [pubgrub](https://github.com/pubgrub-rs/pubgrub) dependency resolution library as [`uv`](https://docs.astral.sh/uv/)
- ✅ designed for flexibility - `gipm` utilizes semantic version ranges, improving flexibility over submodule limitations
- 🔒 designed for repeatability - `gipm` provides a .lock file to guarantee repeatability when necessary
- 🧠 designed for portability - `gipm` utilizes the [`gix`](https://github.com/GitoxideLabs/gitoxide) library to drive its git interactions; no need to manage any external tooling.
  - Note: `gix` is still undergoing heavy development. Currently, `gix` has limited support for submodules, and if a dependency is cloned containing a submodule, they be recursively initialized using `git` for the time being.
  - TODO: maybe use a `git2` binding?

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

## Limitations

- This tool requires dependencies follow [semantic versioning](https://semver.org/) practices on their git repositories, and manage a **consistent tag format** that represents each release. This is best practice and generally adhered to across most repositories.
- Dependencies with git submdodules may define the system in such a way that multiple copies of a dependency exists in your workspace (i.e. one copy in .gitvenv, and one as a submodule of a dependency). There is no way around this currently.
- Beware of pitfalls with yaml specifications - [the yaml document from hell](https://ruudvanasseldonk.com/2023/01/11/the-yaml-document-from-hell) is a good read
  - Note: YAML may be rethunk here in the future, but it is nice for its ease of reading for the user.
