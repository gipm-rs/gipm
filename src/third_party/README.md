The code in this folder has been copied from another location. Source modifications have been minimal to resolve imports and handle features only. Original licensing applies.

- semver_pubgrub: https://github.com/pubgrub-rs/semver-pubgrub
  - ref = `7661ab93f3217021d02ce99c8e96e5802af1c43a`
  - reason: this is not published on crates.io
  * changes:
    - removed examples/fuzz
    - only included src
    - renamed lib.rs -> mod.rs
    - updated `use` syntax for `crate::third_party::semver_pubgrub::`
    - deleted cargo.toml, cargo.lock, .gitignore
    - removed `serde` features
