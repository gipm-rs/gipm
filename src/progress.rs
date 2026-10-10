//! Progress rendering for `gipm`.
//!
//! `prodash` is only the data model: gix's progress callbacks are typed against its
//! tree items, so the items have to stay prodash items. The drawing is done by
//! `indicatif` (on top of `console`), which owns the cursor: one bar for the whole
//! phase, one bar per task below it, repainted in place. While bars are alive nothing
//! else writes to `stderr`; log lines are handed to this module and printed above the
//! bar block, which is what keeps the cursor from jumping around.
//!
//! Nothing outside this module touches `prodash`, `indicatif` or `console`.

use once_cell::sync::Lazy;
use crossterm::tty::IsTty;
use console::{Term};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use prodash::messages::{Message, MessageLevel};
use prodash::progress::{Key, Task};
use prodash::progress::key::Level;
use prodash::tree::Root;
use gix::progress::prodash::tree::Item;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::io::stderr;
use std::thread::{JoinHandle, sleep, spawn};
use std::time::Duration;
use std::cmp::max;
use std::cmp::min;

const FRAME_MS: u64 = 100;
const PREFIX_WIDTH: u16 = 22;
const TRAIL_WIDTH: u16 = 26;
const MIN_BAR_WIDTH: u16 = 8;
const MAX_BAR_WIDTH: u16 = 100;

/// Braille dots, the usual "still working, unknown size" spinner. The last entry
/// is the frame used once a task reports completion, so it repeats the first one.
const SPINNER: &[&str] = &[
    "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠋",
];
const MAX_TASKS: usize = 30;

static PROGRESS: Lazy<Arc<Root>> = Lazy::new(|| {
    prodash::tree::root::Options {
        message_buffer_capacity: 400,
        ..Default::default()
    }.into()
});

static RENDERER_ENABLED: AtomicBool = AtomicBool::new(true);
static BARS_ALIVE: AtomicBool = AtomicBool::new(false);

/// Set by the render thread when it leaves the frame loop, so a `ProgressHandle` can be
/// shut down (or dropped) without owning the `JoinHandle`.
static RENDER_EXITED: AtomicBool = AtomicBool::new(false);

/// Cached tty-ness of `stderr` (see `stderr_is_tty`).
static STDERR_TTY: AtomicBool = AtomicBool::new(false);
static STDERR_TTY_KNOWN: AtomicBool = AtomicBool::new(false);

/// True when `stderr` can actually take cursor control. Bars are only ever drawn to
/// `stderr`, so this is also the gate for "may I own the cursor".
fn stderr_is_tty() -> bool {
    if STDERR_TTY_KNOWN.load(Ordering::Relaxed) {
        return STDERR_TTY.load(Ordering::Relaxed)
    }

    // Resolved once: tty-ness cannot change mid-run, and the Windows implementation of
    // the check is a handful of console API calls, which a hot log path would otherwise
    // pay on every single line.
    let tty: bool = stderr().is_tty();
    STDERR_TTY.store(tty, Ordering::Relaxed);
    STDERR_TTY_KNOWN.store(true, Ordering::Relaxed);
    tty
}

static PENDING: Lazy<Mutex<Vec<String>>> = Lazy::new(|| {
    Mutex::new(vec![])
});

/// How many package-level tasks the running phase is expected to handle. The
/// prodash tree only ever holds work that is *currently* running (items are
/// removed as soon as their `Item` goes out of scope), so it cannot answer "how
/// far along am I"; the caller knows the real number and hands it over.
static EXPECTED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Package-level tasks that finished, name-deduped.
static DONE_COUNT: AtomicU64 = AtomicU64::new(0);

static DONE_NAMES: Lazy<Mutex<Vec<String>>> = Lazy::new(|| {
    Mutex::new(vec![])
});

/// Turns bar rendering on or off (`--no-progress`). Items keep being recorded so gix
/// callbacks stay happy, they simply are not drawn.
pub fn set_enabled(enabled: bool) {
    RENDERER_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    RENDERER_ENABLED.load(Ordering::Relaxed)
}

/// True while a render thread owns the `stderr` cursor.
pub fn bars_alive() -> bool {
    BARS_ALIVE.load(Ordering::Relaxed)
}

/// True when bars would actually be drawn: requested *and* the stream can take them.
/// Anything that decides "route this line through the renderer or straight to `stderr`"
/// must use this, never `enabled()` alone — indicatif silently drops every frame (and
/// every `println`) once `stderr` is not a terminal, so a piped run that thinks it has
/// bars loses all of its log output.
pub fn drawing() -> bool {
    enabled() && stderr_is_tty()
}

/// Writes one line to `stderr`, or queues it for the renderer while bars are alive so
/// the bar block never gets scribbled over.
pub fn write_line(text: String) {
    if bars_alive() {
        PENDING.lock().unwrap().push(text);
    } else {
        let _ = Term::stderr().write_line(&text);
    }
}

/// Hands over everything queued since the last frame.
pub fn drain_pending() -> Vec<String> {
    let mut lock = PENDING.lock().unwrap();
    let lines: Vec<String> = lock.to_vec();
    lock.clear();
    lines
}

/// Flush anything still queued, used when the renderer goes away.
pub fn flush_pending() {
    for line in drain_pending() {
        let _ = Term::stderr().write_line(&line);
    }
}

/// A top-level item, folded together with its nested children.
#[derive(Clone)]
pub struct BarSpec {
    pub key: Key,
    pub name: String,
    pub current: u64,
    pub total: u64,
    pub status: String,
    /// Name of the deepest sub-step that is running, e.g. `fetch` or `checkout`.
    pub stage: String,
    pub done: bool,
}

/// Snapshot of the prodash tree folded into one entry per top-level item.
fn collect_specs() -> Vec<BarSpec> {
    let mut tasks: Vec<(Key, Task)> = vec![];
    PROGRESS.sorted_snapshot(&mut tasks);

    let mut messages: Vec<Message> = vec![];
    PROGRESS.copy_messages(&mut messages);

    let mut specs: Vec<BarSpec> = vec![];

    for (key, task) in &tasks {
        let level: Level = key.level();

        if level == 1 {
            let mut spec: BarSpec = BarSpec {
                key: *key,
                name: task.name.clone(),
                current: 0,
                total: 0,
                status: "".to_string(),
                stage: "".to_string(),
                done: false,
            };

            if let Some(value) = &task.progress {
                spec.current += value.step.load(Ordering::Relaxed) as u64;

                if let Some(max) = &value.done_at {
                    spec.total += *max as u64;
                }
            }

            specs.push(spec);
        } else if level > 1 {
            for spec in specs.iter_mut() {
                if key.shares_parent_with(&spec.key, 1) {
                    if let Some(value) = &task.progress {
                        spec.current += value.step.load(Ordering::Relaxed) as u64;

                        if let Some(max) = &value.done_at {
                            spec.total += *max as u64;
                        }
                    }

                    spec.stage = task.name.clone();
                }
            }
        }
    }

    for message in &messages {
        for spec in specs.iter_mut() {
            if spec.name == message.origin {
                spec.status = message.message.clone();
                spec.done = message.level != MessageLevel::Info;
            }
        }
    }

    specs
}

/// The bar look: a thin rule that fills cyan and turns green when the task is
/// finished. Unicode everywhere — `cmd.exe` on a legacy codepage is the one place
/// this can look odd, and `--plain` (no bars at all) is the escape hatch.
fn bar_style(term: Term, done: bool) -> ProgressStyle {
    let chars: String = "━╌ ".to_string();

    let width: u16 = term.size().1;
    let mut bar_width: u16 = MIN_BAR_WIDTH;

    if width > PREFIX_WIDTH + TRAIL_WIDTH {
        bar_width = (width - PREFIX_WIDTH - TRAIL_WIDTH).clamp(MIN_BAR_WIDTH, MAX_BAR_WIDTH);
    }

    let template: String = format!(
        "{{prefix:>{}!.bold}} {{bar:{}.{}{}}} {{percent:>3}}% {{elapsed}} {{msg:.{}}}",
        PREFIX_WIDTH,
        bar_width,
        if done { "green" } else { "cyan" },
        if done { "/dark_gray" } else { "/blue" },
        if done { "green" } else { "cyan" },
    );

    match ProgressStyle::with_template(&template) {
        Ok(style) => style.progress_chars(&chars),
        Err(_) => ProgressStyle::default_bar().progress_chars(&chars),
    }
}

/// Used for tasks whose total is not yet known, where a bar would just be empty.
/// A braille spinner is the honest signal there: work is happening, the size is not.
fn spinner_style() -> ProgressStyle {
    let template: String = format!(
        "{{prefix:>{}!.bold}} {{spinner:1.cyan}} {{elapsed}} {{msg:.dim}}",
        PREFIX_WIDTH,
    );

    match ProgressStyle::with_template(&template) {
        Ok(style) => style.tick_strings(SPINNER),
        Err(_) => ProgressStyle::default_spinner().tick_strings(SPINNER),
    }
}

/// The phase bar: same rule as the task bars, plus a spinner so the eye always
/// has something moving while work is running.
fn overall_style(term: Term) -> ProgressStyle {
    let chars: String = "━╌ ".to_string();

    let width: u16 = term.size().1;
    let mut bar_width: u16 = MIN_BAR_WIDTH;

    if width > PREFIX_WIDTH + TRAIL_WIDTH + 2 {
        bar_width = (width - PREFIX_WIDTH - TRAIL_WIDTH - 2).clamp(MIN_BAR_WIDTH, MAX_BAR_WIDTH);
    }

    let template: String = format!(
        "{{prefix:>{}!.bold}} {{spinner:1.cyan}} {{bar:{}.cyan/blue}} {{percent:>3}}% {{elapsed}} {{msg:.cyan}}",
        PREFIX_WIDTH,
        bar_width,
    );

    match ProgressStyle::with_template(&template) {
        Ok(style) => style.progress_chars(&chars).tick_strings(SPINNER),
        Err(_) => ProgressStyle::default_bar().progress_chars(&chars),
    }
}
/// Owns the bars and the cursor for one render thread. Everything that repaints
/// `stderr` lives here so nothing else can fight over the cursor.
pub struct Renderer {
    pub multi: MultiProgress,
    pub overall: ProgressBar,
    pub bars: Vec<(Key, ProgressBar, BarSpec, u64)>,
    pub total_seen: u64,
    pub done_seen: u64,
    pub style: ProgressStyle,
    pub done_style: ProgressStyle,
    pub spinner_style: ProgressStyle,
    pub overall_style: ProgressStyle,
}

impl Renderer {
    pub fn new(multi: MultiProgress, style: ProgressStyle, done_style: ProgressStyle, spinner_style: ProgressStyle, overall_style: ProgressStyle) -> Renderer {
        let overall: ProgressBar = multi.add(ProgressBar::no_length());
        overall.set_style(overall_style.clone());

        Renderer {
            multi,
            overall,
            bars: vec![],
            total_seen: 0,
            done_seen: 0,
            style,
            done_style,
            spinner_style,
            overall_style,
        }
    }

    /// Repaints the bar block from a fresh snapshot. Bars are keyed by the prodash
    /// item they came from, not by position: when a sibling task finishes and the
    /// snapshot shrinks around it, every other task keeps its own bar instead of
    /// sliding onto the next one (which is what made bars jump back from 100%).
    pub fn draw(&mut self, specs: Vec<BarSpec>) {
        // The overall spinner is advanced by us, not by a per-bar ticker: a ticker
        // spawns its own thread that redraws a single bar, which inside a MultiProgress
        // prints a stray copy of the line (that is what produced a second "total" bar).
        self.overall.tick();

        let drawn: usize = min(MAX_TASKS, specs.len());

        for spec in specs.iter().take(drawn) {
            let index: usize = match self.bars.iter().position(|(key, _, _, _)| *key == spec.key) {
                Some(index) => index,
                None => {
                    let bar: ProgressBar = if spec.total > 0 {
                        ProgressBar::new(spec.total)
                    } else {
                        ProgressBar::no_length()
                    };

                    self.bars.push((spec.key, self.multi.add(bar), spec.clone(), spec.total));
                    self.bars.len() - 1
                },
            };

            let was_done: bool = self.bars[index].2.done;
            self.bars[index].2 = spec.clone();

            if was_done {
                // Completion is sticky: a task that reported done stays done even if
                // a later snapshot still shows it (or shows it without a message).
                self.bars[index].2.done = true;
            }

            self.bars[index].1.set_style(
                if spec.done {
                    self.done_style.clone()
                } else if spec.total > 0 {
                    self.style.clone()
                } else {
                    self.spinner_style.clone()
                }
            );
            self.bars[index].1.set_prefix(spec.name.clone());

            if spec.total > 0 {
                // A task's total can grow as more sub-steps show up (gix reports them
                // lazily); never let the track shrink, that reads as lost progress.
                let length: u64 = max(spec.total, self.bars[index].3);
                self.bars[index].3 = length;
                self.bars[index].1.set_length(length);
                self.bars[index].1.set_position(min(spec.current, length));
            } else if spec.done {
                // Nothing ever reported a total for this task; a finished one still
                // deserves a full bar rather than an empty track.
                self.bars[index].1.set_length(1);
                self.bars[index].1.set_position(1);
            }

            // A task's own message wins; otherwise show which sub-step is running so
            // a long clone does not look like the same bar sitting still.
            self.bars[index].1.set_message(
                if spec.status.is_empty() {
                    spec.stage.clone()
                } else {
                    spec.status.clone()
                }
            );

            if !spec.done && spec.total == 0 {
                self.bars[index].1.tick();
            }
        }

        // Tasks that left the tree and never finished are gone: drop their bar.
        let mut index: usize = 0;
        while index < self.bars.len() {
            let (key, _, spec, _) = &self.bars[index];
            let alive: bool = specs.iter().any(|spec| spec.key == *key);

            if !alive && !spec.done {
                self.multi.remove(&self.bars[index].1);
                self.bars.remove(index);
            } else {
                index += 1;
            }
        }

        let message_done: u64 = self.bars.iter().filter(|(_, _, spec, _)| spec.done).count() as u64;
        let done: u64 = max(done_count(), message_done);

        // The prodash tree only ever holds work that is *currently* running, so it can
        // never be the denominator. Until the caller hands the real one over
        // (`set_expected`), the honest drawing is a spinner with a running count — a bar
        // sized by "tasks alive right now" reads as progress that goes backwards the
        // moment the solver reports its true size.
        let expected: u64 = expected_total();

        if expected == 0 {
            self.overall.set_style(self.spinner_style.clone());
            self.overall.set_prefix("total".to_string());
            self.overall.set_message(
                if specs.len() > drawn {
                    format!("{} running, {} more", self.bars.len(), specs.len() - drawn)
                } else {
                    format!("{} running", self.bars.len())
                },
            );
            return
        }

        let total: u64 = expected;

        self.done_seen = done;
        self.total_seen = total;

        self.overall.set_length(total);
        self.overall.set_position(min(done, total));
        self.overall.set_prefix("total".to_string());
        self.overall.set_message(
            if specs.len() > drawn {
                format!("{} of {} packages, {} bars not shown", done, total, specs.len() - drawn)
            } else {
                format!("{} of {} packages", done, total)
            },
        );
    }

    /// Prints a log line above the bar block, keeping the cursor bookkeeping intact.
    pub fn print(&mut self, line: String) {
        let _ = self.multi.println(line);
    }

    pub fn clear(&mut self) {
        let _ = self.multi.clear();
    }
}

fn render_loop(stop: Arc<AtomicBool>) {
    let term: Term = Term::buffered_stderr();
    let style: ProgressStyle = bar_style(term.clone(), false);
    let done_style: ProgressStyle = bar_style(term.clone(), true);
    let mut renderer: Renderer = Renderer::new(
        MultiProgress::new(),
        style,
        done_style,
        spinner_style(),
        overall_style(term.clone()),
    );

    while !stop.load(Ordering::Relaxed) {
        renderer.draw(collect_specs());

        for line in drain_pending() {
            renderer.print(line);
        }

        sleep(Duration::from_millis(FRAME_MS));
    }

    for line in drain_pending() {
        renderer.print(line);
    }

    renderer.clear();
    RENDER_EXITED.store(true, Ordering::Relaxed);
}

/// Starts the renderer for one phase. `expected` is the number of package-level
/// tasks the phase will handle; pass 0 and call `set_expected` once that number
/// is known (e.g. after the solver has resolved the graph).
pub fn start(expected: usize) -> ProgressHandle {
    // No bars when `stderr` is not a terminal: indicatif would drop every frame anyway,
    // and the log lines that used to ride along with them would be dropped too.
    if !drawing() || bars_alive() {
        return ProgressHandle { stop: None }
    }

    DONE_COUNT.store(0, Ordering::Relaxed);
    DONE_NAMES.lock().unwrap().clear();
    RENDER_EXITED.store(false, Ordering::Relaxed);
    set_expected(expected);

    let stop: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    BARS_ALIVE.store(true, Ordering::Relaxed);

    let shared: Arc<AtomicBool> = stop.clone();

    // The thread is deliberately detached: it exits as soon as `stop` flips, and
    // `stop_and_wait` waits for `RENDER_EXITED` instead of joining a handle it cannot
    // move out of a type that has a user-defined `Drop`.
    let _thread: JoinHandle<()> = spawn(|| {
        render_loop(shared)
    });

    ProgressHandle { stop: Some(stop) }
}

pub struct ProgressHandle {
    pub stop: Option<Arc<AtomicBool>>
}

impl ProgressHandle {
    /// Stop the render thread, clear the bar block and flush queued log lines. Rarely
    /// needed: dropping the handle does the same thing, and a `?` early return drops it
    /// for you. Kept for the call sites that want the bars gone *before* they print the
    /// summary table.
    pub fn shutdown_and_wait(self: ProgressHandle) {
        stop_and_wait(&self)
    }
}

/// The handle is a real RAII guard: a phase that bails out through `?` (a bad
/// `dependencies.yaml`, an unsolvable graph, …) still stops the render thread, clears
/// the bar block and flushes queued log lines before anything else touches `stderr`.
impl Drop for ProgressHandle {
    fn drop(&mut self) {
        stop_and_wait(self)
    }
}

/// The shared shutdown path. The render thread is not joined (its `JoinHandle` is
/// deliberately detached, and a type with a user-defined `Drop` cannot have fields moved
/// out of it), so the way to know it is gone is the flag it sets when the frame loop
/// unwinds — waiting for that is exactly what `join` would guarantee.
fn stop_and_wait(handle: &ProgressHandle) {
    if let Some(stop) = &handle.stop {
        stop.store(true, Ordering::Relaxed);

        while !RENDER_EXITED.load(Ordering::Relaxed) {
            sleep(Duration::from_millis(1));
        }
    }

    BARS_ALIVE.store(false, Ordering::Relaxed);
    flush_pending();
}

/// Tells the renderer how many package-level tasks the phase is expected to do,
/// which is the only honest denominator for the overall bar.
pub fn set_expected(total: usize) {
    EXPECTED_TOTAL.store(total as u64, Ordering::Relaxed);
}

pub fn expected_total() -> u64 {
    EXPECTED_TOTAL.load(Ordering::Relaxed)
}

pub fn done_count() -> u64 {
    DONE_COUNT.load(Ordering::Relaxed)
}

/// Marks one package-level task as finished. Names are deduped so a task that
/// reports both a stage and a final status is not counted twice.
pub fn task_done(name: String) {
    let mut lock = DONE_NAMES.lock().unwrap();

    if lock.iter().any(|done| done == &name) {
        return
    }

    lock.push(name.clone());
    DONE_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// A top-level item: gets its own bar.
pub fn child(message: String) -> Item {
    PROGRESS.add_child(message)
}

/// A nested item: recorded for gix callbacks, folded into its parent's bar.
pub fn subchild(parent: &mut Item, message: String) -> Item {
    parent.add_child(message)
}

#[cfg(test)]
#[test]
fn test_progress_frame() -> anyhow::Result<()> {
    use indicatif::{InMemoryTerm, ProgressDrawTarget};

    let mut zlib: Item = child("zlib".to_string());
    let fetch: Item = zlib.add_child("fetch".to_string());
    fetch.init(Some(10), gix::progress::count("files"));
    fetch.set(4);

    let mut curl: Item = child("curl".to_string());
    curl.done("fetched".to_string());
    task_done("curl".to_string());

    set_expected(3);

    let openssl: Item = child("openssl".to_string());
    openssl.inc();
    openssl.inc();

    let specs: Vec<BarSpec> = collect_specs();

    for index in 0..specs.len() {
        eprintln!("spec {}: {} {} / {} done={}", index, specs[index].name, specs[index].current, specs[index].total, specs[index].done);
    }

    anyhow::ensure!(
        specs.len() == 3,
        "expected exactly one bar per top level item, got {}",
        specs.len()
    );

    let style: ProgressStyle = bar_style(Term::buffered_stderr(), false);
    let done_style: ProgressStyle = bar_style(Term::buffered_stderr(), true);
    let term: InMemoryTerm = InMemoryTerm::new(24, 200);
    let target: ProgressDrawTarget = ProgressDrawTarget::term_like_with_hz(Box::new(term.clone()), 20);

    let mut renderer: Renderer = Renderer::new(
        MultiProgress::with_draw_target(target),
        style,
        done_style,
        spinner_style(),
        overall_style(Term::buffered_stderr()),
    );
    renderer.draw(collect_specs());

    let frame: String = term.contents();
    eprintln!("rendered frame:\n{}", frame);

    anyhow::ensure!(frame.contains("zlib"), "the task name must be drawn as prefix");
    anyhow::ensure!(frame.contains("curl"), "every top level item must get a bar");
    anyhow::ensure!(frame.contains("40%"), "nested progress must fold into the parent bar");
    anyhow::ensure!(frame.contains("openssl"), "unknown-total tasks must still get a line");
    anyhow::ensure!(
        SPINNER.iter().any(|f| frame.contains(*f)),
        "unknown-total tasks must get a spinner",
    );
    anyhow::ensure!(
        frame.find("of 3 packages") != None,
        "the overall bar must count against the phase total, not the live task count",
    );

    let overall_lines: usize = frame.split('\n')
        .map(|line| line.to_string())
        .filter(|line| line.find("packages") != None)
        .count();

    anyhow::ensure!(overall_lines == 1, "the overall bar must be drawn exactly once, got {}", overall_lines);

    renderer.clear();
    return Ok(())
}
