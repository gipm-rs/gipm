bugs:

- prefix finder seems to not be so good
- zlib when specified as 1.2.13 seems to be matching >= 1.2.13, is this normal?
- fix submodule clones?
  - something with openssl and permissions is weird here
- syncing followed by update always pulls some tag refs,

todo:

- tests: the four integration targets are now hermetic (fixture repos over `file://`,
  per-test database cache, lockfile generated in-test). Still open: a fixture carrying a
  real submodule, and one whose default branch is not `main`.

logging/progress (done, see docs/plans/logging-overhaul.md):

- `src/logging.rs` owns all diagnostics (`log` macros, level flags, colour policy, summary table)
- `src/progress.rs` is the only `prodash`/`indicatif`/`console` touch point: `prodash` is the item tree gix writes into, `indicatif` draws one overall bar plus one bar per package; `--no-progress` and `--plain` skip the render thread entirely
- remaining caveat: nested gix items are still recorded in the tree (they have to be, gix owns the callbacks); they are folded into their parent bar (progress summed, sub-step name shown as the bar's status) instead of drawn as their own line
- done in follow-up: submodule updates now have their own bar (`init(count)` + one step per fetched submodule, streamed from the child's stderr) instead of a silent `git` call; the overall bar counts against `progress::start(expected)`/`set_expected` and `task_done(name)`, not the live tree; the summary table is coloured from the same palette as the bars and carries the resolved commit sha

