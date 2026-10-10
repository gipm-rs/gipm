# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 📖 Overview

The `gipm` (Git Package(like) Manager) is a tool designed to manage complex, multi-layered dependencies for languages without strong native package management systems (e.g., C/C++, Fortran). It uses semantic versioning and git interactions to resolve and manage external dependencies, aiming to achieve repeatability and flexibility that standard git submodules lack.

## 🚀 Core Commands and Workflow

The primary workflow involves three steps:

1.  **Define Dependencies:** Specify external dependencies and their version ranges in a `dependencies.yaml` file.
2.  **Update/Resolve:** Run `gipm update` or `gipm sync` to resolve the dependency graph, which utilizes `pubgrub-rs` for efficient solving.
3.  **Checkout/Use:** The resolved dependencies are cloned or updated into the local `.gitvenv` directory for use by the project.

Key commands:
*   `gipm update`: Updates the package versions based on the ranges defined in `dependencies.yaml`.
*   `gipm sync`: Synchronizes the repository state to match the versions defined in the generated lockfile.
*   `gipm clean`: Removes the `.gitvenv` directory.
*   `gipm --help`: Displays detailed usage.

**Development Best Practice:** When working with dependencies, always ensure that changes are reflected by running `gipm update` or `gipm sync` and validating that the `.gitvenv` state matches the intended build environment.

## 🏗️ Architecture & Structure

The repository's architecture revolves around the following key components:

*   **`src/`**: Contains the core logic of the `gipm` CLI tool.
    *   `src/lib.rs`: The main library entry point.
    *   `src/main.rs`: The application entry point.
    *   `src/resolver.rs`: Handles the dependency resolution logic, likely interfacing with the `pubgrub` library.
    *   `src/logging.rs`: The logging backend (`log` facade + level/colour resolution). Diagnostics go to `stderr`, the result summary table goes to `stdout`; never use bare `println!`/`eprintln!` for status reporting. The table is boxed (`┌┬┐` styled, `+` plain), padded by visible width, fitted to the terminal by truncating the widest columns with `…` (only when styled, so redirected output stays lossless), and drops any column that carries no data anywhere. Cells are coloured from the same palette as the bars (bold package, cyan version, grey tag/sha, green or yellow status); the `commit` column carries the resolved sha, so a report shows tag *and* commit.
    *   `src/progress.rs`: The only place `prodash`, `indicatif` and `console` are referenced. `prodash` is the data model (gix progress callbacks are typed against its tree items); `indicatif` draws the bars — one overall bar, one bar per package, a braille spinner for tasks whose size is not known yet. Bars are keyed by the prodash item, never by position, and bar lengths/counters are monotonic. The overall bar's denominator comes from `progress::start(expected)` / `progress::set_expected(n)` and its numerator from `progress::task_done(name)` — the prodash tree only holds *currently running* work (items are removed when their `Item` goes out of scope), so it can never be a denominator. Use `progress::start(...)`, `progress::child(...)`, `progress::subchild(...)`. Never call `ProgressBar::enable_steady_tick` on a bar that lives in a `MultiProgress` — its ticker thread redraws that single bar and prints a stray duplicate line; the render thread ticks instead. Never write to `stderr` directly while bars are alive — go through `progress::write_line` so the bar block is never scribbled over. In indicatif templates only `:` separates the key from width/style, so `{msg.cyan}` is read as the key `msg.cyan` and renders nothing — write `{msg:.cyan}`.
    *   `src/third_party/`: Contains local copies or wrappers for external libraries used by `gipm` (e.g., `semver_pubgrub/`).
*   **`dependencies.yaml`**: The primary input file, defining the top-level dependency graph.
*   **`gitoxide` integration**: The tool uses the [`gix`](https://github.com/GitoxideLabs/gitoxide) library for its git interactions, enabling efficient, in-process extraction of git metadata for dependency resolution.

## ⚙️ Advanced Concepts

*   **Dependency Resolution**: `gipm` reads `dependencies.yaml` and recursively resolves dependencies, facilitating the management of complex, nested dependency trees.
*   **Working Directory**: The resolved, checked-out dependencies are managed within the `.gitvenv` directory.
*   **Versioning**: The system relies heavily on semantic versioning (following [cargo version requirement syntax](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#version-requirement-syntax)) and requires dependencies to maintain consistent tag formats.

## 🚨 Limitations and Caveats

1.  **Git Submodules**: This system is explicitly designed to solve the pain points of using nested git submodules.
2.  **Existing Dependencies**: If a dependency already has its own internal dependencies, they might appear in both the `.gitvenv` and as submodules, which is currently unavoidable.
3.  **Language Scope**: `gipm` is a general-purpose dependency manager and should *not* replace language-specific managers like `cargo`, `npm`, or `uv` when working within a strongly supported ecosystem.
