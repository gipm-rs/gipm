bugs:

- prefix finder seems to not be so good
- zlib when specified as 1.2.13 seems to be matching >= 1.2.13, is this normal?
- submodule clones: the `git` cli fallback is gone (see logging/progress notes below), so the
  openssl/permissions symptom this entry described was the unusable database residue under
  `~/.gipm/db`, which `database_is_usable` now treats as absent and re-clones.
  Still unverified against a real submodule fixture (see tests below).
- syncing followed by update always pulls some tag refs,

todo:

- tests: the four integration targets are now hermetic (fixture repos over `file://`,
  per-test database cache, lockfile generated in-test). Still open: a fixture carrying a
  real submodule, and one whose default branch is not `main`.

logging/progress (done, see docs/plans/logging-overhaul.md):

- `src/logging.rs` owns all diagnostics (`log` macros, level flags, colour policy, summary table)
- `src/progress.rs` is the only `prodash`/`indicatif`/`console` touch point: `prodash` is the item tree gix writes into, `indicatif` draws one overall bar plus one bar per package; `--no-progress` and `--plain` skip the render thread entirely
- remaining caveat: nested gix items are still recorded in the tree (they have to be, gix owns the callbacks); they are folded into their parent bar (progress summed, sub-step name shown as the bar's status) instead of drawn as their own line
- submodule handling no longer shells out to `git`: each submodule is read from the parent index (`gix::Repository::submodules()`), its mount point and pinned OID come from that index, its relative URL is resolved against the parent's remote, and it is cloned through the same object-clone path as its parent — so its progress arrives in gix's tree instead of being scraped from the cli's stderr. `update = none` is honoured; `--depth 1` is now unconditional (the cli flag was always passed); recursion is natural because that clone path ends by walking the submodule table again. Still open: no fixture exercises it, and `--jobs` parallelism per submodule was dropped.
- done in follow-up: submodule updates now have their own bar (`init(count)` + one step per fetched submodule, streamed from the child's stderr) instead of a silent `git` call; the overall bar counts against `progress::start(expected)`/`set_expected` and `task_done(name)`, not the live tree; the summary table is coloured from the same palette as the bars and carries the resolved commit sha

