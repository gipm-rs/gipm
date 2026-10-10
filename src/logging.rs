//! Rich, level-based logging for `gipm`.
//!
//! Log records go to `stderr`; the result summary goes to `stdout`.
//!
//! Levels: default `warn`, `-v` `info`, `-vv` `debug`, `-vvv` `trace`, `-q` `error`,
//! `--log-level <level>` overrides, `RUST_LOG` honoured when no flags are given (only the
//! level part of a spec such as `gipm=debug` is honoured; there is no module scoping).
//!
//! "What the command just did" (lockfile path, `clean`'s result, the success footer) is
//! not a log level — it goes through `result()`, which prints whatever the level is.
//! Third-party `info!` chatter (pubgrub logs a lot) would otherwise flood a default run.

use chrono::Local;
use crossterm::tty::IsTty;
use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError, max_level, set_logger, set_max_level, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::cmp::max;
use std::env::var;
use std::io::stderr;

use console::{set_colors_enabled_stderr, Term};
use crate::progress;

use anyhow::Error;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const GREY: &str = "\x1b[90m";

/// Columns never shrink below this; below that the table is unreadable anyway.
const MIN_COL_WIDTH: usize = 6;

static STYLED: AtomicBool = AtomicBool::new(false);
static TIMESTAMPS: AtomicBool = AtomicBool::new(false);
static RESULTS: AtomicBool = AtomicBool::new(true);

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

pub struct InitOptions {
    pub verbosity: u8,
    pub quiet: bool,
    pub color: ColorMode,
    pub plain: bool,
    pub log_level: Option<String>,
}

pub struct SummaryRow {
    pub name: String,
    pub version: String,
    pub tag: String,
    pub commit: String,
    pub status: String,
}

struct GipmLogger;

impl Log for GipmLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level().to_level_filter() <= max_level()
    }

    fn log(&self, record: &Record) {
        if record.level().to_level_filter() > max_level() {
            return;
        }

        let prefix: String = if TIMESTAMPS.load(Ordering::Relaxed) {
            format!("{} ", timestamp())
        } else {
            "".to_string()
        };

        let message: String = format!("{}", record.args());
        progress::write_line(format!("{}{}{}", prefix, level_tag(record.level()), indent_continuation(&message)));
    }

    fn flush(&self) {}
}

static LOGGER: GipmLogger = GipmLogger;

/// Installs the backend and resolves the level. Idempotent: a second call only
/// refreshes level and style flags, which keeps library embedding (and tests) safe.
pub fn init(options: InitOptions) {
    STYLED.store(style_enabled(&options), Ordering::Relaxed);
    let results_off: bool = options.quiet
        || match options.log_level {
            Some(ref spec) => spec.to_lowercase() == "off" || spec.to_lowercase() == "none" || spec.to_lowercase() == "quiet",
            None => false,
        };

    RESULTS.store(!results_off, Ordering::Relaxed);

    // `console`/`indicatif` keep their own colour switch; keep it in sync with ours so
    // bars and log lines agree on whether the stream can take ANSI.
    set_colors_enabled_stderr(STYLED.load(Ordering::Relaxed));

    let explicit: Option<String> = options.log_level.clone();

    let filter: LevelFilter = resolve_level(options);
    TIMESTAMPS.store(filter >= LevelFilter::Debug, Ordering::Relaxed);

    // "already initialized" is not an error here: tests link the library next to main().
    let _installed: Result<(), SetLoggerError> = set_logger(&LOGGER);

    set_max_level(filter);

    if let Some(spec) = explicit
        && parse_level_name(&spec).is_none()
            && parse_rust_log(&spec).is_none() {
                warn!(
                    "unrecognized --log-level '{}', falling back to the flag count", spec
                );
            }
}

pub fn current_level() -> LevelFilter {
    max_level()
}

/// Level precedence: `--log-level` > `RUST_LOG` (only when no flags) > `-q` > `-v` count.
pub fn resolve_level(options: InitOptions) -> LevelFilter {
    if let Some(spec) = options.log_level {
        if let Some(filter) = parse_level_name(&spec) {
            return filter;
        }
        if let Some(filter) = parse_rust_log(&spec) {
            return filter;
        }
    }

    if options.verbosity == 0 && !options.quiet
        && let Ok(spec) = var("RUST_LOG")
            && let Some(filter) = parse_rust_log(&spec) {
                return filter;
            }

    if options.quiet {
        return LevelFilter::Error;
    }

    // `warn` is the floor because pubgrub logs its own reasoning at `info!`; the user-facing
    // result lines do not ride on a level, they go through `result()`.
    match options.verbosity {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

pub fn parse_level_name(value: &str) -> Option<LevelFilter> {
    let name: String = value.to_lowercase();

    match name.as_str() {
        "off" => Some(LevelFilter::Off),
        "none" => Some(LevelFilter::Off),
        "quiet" => Some(LevelFilter::Off),
        "error" => Some(LevelFilter::Error),
        "err" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "warning" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        "all" => Some(LevelFilter::Trace),
        _ => None,
    }
}

/// Accepts `info`, `my_module=trace`, comma separated; the loudest wins. The module
/// prefix is accepted but ignored — `gipm` installs a single logger, so `gipm=debug`
/// and `=debug` mean the same thing.
pub fn parse_rust_log(spec: &str) -> Option<LevelFilter> {
    let mut best: Option<LevelFilter> = None;

    for token in spec.split(',') {
        let mut name: &str = token;
        if let Some(pos) = token.find('=') {
            name = &token[(pos + 1)..];
        }

        if let Some(filter) = parse_level_name(name) {
            best = loudest(best, filter);
        }
    }

    best
}

fn loudest(current: Option<LevelFilter>, candidate: LevelFilter) -> Option<LevelFilter> {
    if let Some(existing) = current {
        if candidate > existing {
            return Some(candidate);
        }
        return Some(existing);
    }

    Some(candidate)
}

/// True when ANSI should be emitted: never under `--plain`/`--color never`, always under
/// `--color always`, otherwise only when `stderr` is a terminal.
fn style_enabled(options: &InitOptions) -> bool {
    if options.plain {
        return false;
    }

    match options.color {
        ColorMode::Never => false,
        ColorMode::Always => true,
        ColorMode::Auto => stderr().is_tty(),
    }
}

fn style(code: &str, text: &str) -> String {
    if STYLED.load(Ordering::Relaxed) {
        return format!("{}{}{}", code, text, RESET);
    }

    text.to_string()
}

/// Status/section glyphs: ASCII only, so Windows consoles never see mojibake.
pub fn sym_ok() -> String {
    style(GREEN, "ok")
}

pub fn sym_warn() -> String {
    style(YELLOW, "~")
}

pub fn sym_fail() -> String {
    style(RED, "xx")
}

pub fn sym_dirty() -> String {
    style(YELLOW, "dirty")
}

pub fn sym_lock() -> String {
    style(CYAN, "#")
}

fn level_color(level: Level) -> &'static str {
    match level {
        Level::Error => RED,
        Level::Warn => YELLOW,
        Level::Info => DIM,
        Level::Debug => GREY,
        Level::Trace => GREY,
    }
}

fn level_tag(level: Level) -> String {
    let code: &str = level_color(level);
    let name: String = format!("{:<5}", level.as_str());

    format!("{}{}", style(code, &name), ": ")
}

/// Multi-line messages (anyhow cause chains) get aligned under the tag.
fn indent_continuation(message: &str) -> String {
    message.split('\n').collect::<Vec<&str>>().join("\n       ")
}

fn timestamp() -> String {
    Local::now().format("%H:%M:%S").to_string()
}

/// Message plus its cause chain, one cause per line (the backend indents them).
pub fn error_text(err: &Error) -> String {
    let mut parts: Vec<String> = vec![format!("{}", err)];
    let mut cause = err.source();

    while let Some(next) = cause {
        parts.push(format!("{}", next));
        cause = next.source();
    }

    parts.join("\n")
}

/// A user-facing result line ("what the command just did"). Deliberately not an `info!`:
/// pubgrub logs its own reasoning at `info!`, so `info` cannot be the default level, and
/// these lines must still show up in a default run. Suppressed by `-q` and `--log-level off`.
pub fn result(message: String) {
    if !RESULTS.load(Ordering::Relaxed) {
        return
    }

    progress::write_line(format!("{}{}", level_tag(Level::Info), message));
}

/// Top-level failure report. Bypasses the level filter (a failure is never silent) and
/// goes through `progress::write_line`, so it cannot scribble over a live bar block.
pub fn report_error(err: &Error) {
    let prefix: String = if TIMESTAMPS.load(Ordering::Relaxed) {
        format!("{} ", timestamp())
    } else {
        "".to_string()
    };

    progress::write_line(
        format!(
            "{}{}{}",
            prefix,
            level_tag(Level::Error),
            indent_continuation(&error_text(err)),
        ),
    );
}

/// Rough display width of one code point: combining marks are free, East Asian wide
/// glyphs and emoji take two columns, everything else one. An approximation of
/// `unicode-width` that keeps the summary table aligned without the extra dependency.
fn glyph_width(ch: char) -> usize {
    let cp: u32 = ch as u32;

    let zero_width: bool =
        (0x0300..=0x036f).contains(&cp)
            || (0x200b..=0x200f).contains(&cp)
            || (0xfe00..=0xfe0f).contains(&cp);

    if zero_width {
        return 0;
    }

    let wide: bool =
        (0x1100..=0x115f).contains(&cp)
            || (0x2e80..=0x32ff).contains(&cp)
            || (0x3400..=0x9fff).contains(&cp)
            || (0xac00..=0xd7a0).contains(&cp)
            || (0xff00..=0xff60).contains(&cp)
            || (0xffe0..=0xffe6).contains(&cp)
            || (0x1f000..=0x1f9ff).contains(&cp);

    if wide {
        return 2;
    }

    1
}

/// Display width, ignoring any ANSI styling so coloured cells still line up.
fn visible_width(text: String) -> usize {
    let mut width: usize = 0;
    let mut in_escape: bool = false;

    for ch in text.chars() {
        if in_escape {
            if ch == 'm' {
                in_escape = false;
            }
            continue
        }

        if ch == '\x1b' {
            in_escape = true;
            continue
        }

        width += 1;
    }

    width
}

fn pad(value: &str, width: usize) -> String {
    let used: usize = visible_width(value.to_string());

    if width > used {
        return format!("{}{}", value, " ".repeat(width - used));
    }

    value.to_string()
}

/// Cut a (possibly styled) cell to `limit` visible characters and mark the cut.
fn truncate_visible(text: String, limit: usize) -> String {
    let mut out: String = "".to_string();
    let mut seen: usize = 0;
    let mut in_escape: bool = false;
    let mut open_style: bool = false;

    for ch in text.chars() {
        if in_escape {
            out.push(ch);
            if ch == 'm' {
                in_escape = false;
                open_style = !out.ends_with(RESET)
            }
            continue
        }

        if ch == '\x1b' {
            in_escape = true;
            out.push(ch);
            continue
        }

        if seen >= limit {
            break
        }

        out.push(ch);
        seen += glyph_width(ch);
    }

    if open_style {
        return format!("{}{}", out, RESET)
    }

    out
}

/// Pad a cell to its column, truncating first so the table never wraps. The cut marker
/// is … for styled output and .. for plain output, which must stay pure ASCII.
fn fit_cell(value: String, width: usize) -> String {
    if visible_width(value.clone()) > width {
        let ellipsis: &str =
            if STYLED.load(Ordering::Relaxed) {
                "…"
            } else {
                ".."
            };

        let marker: usize = visible_width(ellipsis.to_string());

        if width > marker {
            return pad(&truncate_visible(value.clone(), width - marker).clone(), width)
        }

        return "".to_string()
    }

    pad(&value.clone(), width)
}

/// Shrink the widest columns until the table fits the terminal, so a wide commit
/// sha cannot push the whole box onto the next line. Only for styled (interactive)
/// output: `--plain` and redirected output stay lossless.
fn fit_widths(widths: Vec<usize>) -> Vec<usize> {
    if !STYLED.load(Ordering::Relaxed) {
        return widths.clone();
    }

    let cols: u16 = Term::buffered_stdout().size().1;

    if cols == 0 {
        return widths.clone();
    }

    let mut w: Vec<usize> = widths.clone();
    let fixed: usize = 3 * w.len() + 1;
    let mut total: usize = fixed;
    for width in w.iter() {
        total += width;
    }

    while total > cols as usize {
        let mut widest: usize = 0;
        for index in 0..w.len() {
            if w[index] > w[widest] {
                widest = index
            }
        }

        if w[widest] <= MIN_COL_WIDTH {
            break
        }

        w[widest] -= 1;
        total -= 1;
    }

    w
}

fn summary_cells(row: &SummaryRow) -> Vec<String> {
    vec![
        style(BOLD, &row.name.clone()),
        style(CYAN, &row.version.clone()),
        style(GREY, &row.tag.clone()),
        style(GREY, &row.commit.clone()),
        row.status.clone(),
    ]
}

/// Box-drawing characters for the table. Unicode only where the terminal is
/// styled (a real terminal or a pipe to a pager); ASCII for `--plain`, redirected
/// output and legacy Windows consoles.
pub struct TableEdges {
    pub top_left: String,
    pub top_mid: String,
    pub top_right: String,
    pub mid_left: String,
    pub mid_mid: String,
    pub mid_right: String,
    pub bot_left: String,
    pub bot_mid: String,
    pub bot_right: String,
    pub fill: String,
    pub vertical: String,
}

fn styled_edges() -> TableEdges {
    TableEdges {
        top_left: "┌".to_string(),
        top_mid: "┬".to_string(),
        top_right: "┐".to_string(),
        mid_left: "├".to_string(),
        mid_mid: "┼".to_string(),
        mid_right: "┤".to_string(),
        bot_left: "└".to_string(),
        bot_mid: "┴".to_string(),
        bot_right: "┘".to_string(),
        fill: "─".to_string(),
        vertical: "│".to_string(),
    }
}

fn plain_edges() -> TableEdges {
    TableEdges {
        top_left: "+".to_string(),
        top_mid: "+".to_string(),
        top_right: "+".to_string(),
        mid_left: "+".to_string(),
        mid_mid: "+".to_string(),
        mid_right: "+".to_string(),
        bot_left: "+".to_string(),
        bot_mid: "+".to_string(),
        bot_right: "+".to_string(),
        fill: "-".to_string(),
        vertical: "|".to_string(),
    }
}

/// One border of the table.
fn border_line(widths: Vec<usize>, left: String, mid: String, right: String, fill: String) -> String {
    let mut parts: Vec<String> = vec![];

    for width in widths.iter() {
        parts.push(fill.repeat(width + 2));
    }

    format!("{}{}{}", left, parts.join(mid.as_str()), right)
}

/// One row of the table.
fn cell_line(cells: Vec<String>, widths: Vec<usize>, vertical: String) -> String {
    let mut parts: Vec<String> = vec![];

    for index in 0..cells.len() {
        parts.push(format!(" {} ", fit_cell(cells[index].clone(), widths[index])));
    }

    format!("{}{}{}", vertical, parts.join(vertical.as_str()), vertical.clone())
}

/// The result table: stdout only, never level-filtered, column aligned.
/// Boxed and styled when the terminal is styled, plain ASCII rules otherwise
/// (`--plain`, redirected output, legacy Windows consoles).
/// Which of the five columns actually carry data. Decided from the raw fields, never
/// from styled cells: `style(CYAN, "")` is an escape pair, so a styled empty cell would
/// otherwise keep a column that shows nothing but whitespace.
pub fn keep_columns(rows: &[SummaryRow]) -> Vec<bool> {
    let raw_of = |row: &SummaryRow| -> Vec<String> {
        vec![
            row.name.clone(),
            row.version.clone(),
            row.tag.clone(),
            row.commit.clone(),
            row.status.clone(),
        ]
    };

    let mut keep: Vec<bool> = vec![];
    for index in 0..5 {
        keep.push(rows.iter().any(|row| {
            let raw: Vec<String> = raw_of(row);
            !raw[index].is_empty()
        }))
    }

    keep
}

pub fn format_summary(title: String, rows: Vec<SummaryRow>) -> String {
    let all_headers: Vec<String> =
        vec!["package".to_string(), "version".to_string(), "tag".to_string(), "commit".to_string(), "status".to_string()];

    // A column that carries no information anywhere is dropped instead of drawn as an
    // empty gutter (sync pins commits, so it has neither a semver nor a tag to show).
    let keep: Vec<bool> = keep_columns(&rows);

    let cells_of = |row: &SummaryRow| -> Vec<String> {
        let all: Vec<String> = summary_cells(row);
        let mut out: Vec<String> = vec![];

        for index in 0..all.len() {
            if keep[index] {
                out.push(all[index].clone());
            }
        }

        out
    };

    let mut headers: Vec<String> = vec![];
    for index in 0..all_headers.len() {
        if keep[index] {
            headers.push(all_headers[index].clone());
        }
    }

    let mut widths: Vec<usize> = vec![];
    for header in headers.iter() {
        widths.push(visible_width(header.clone()));
    }

    for row in rows.iter() {
        let cells: Vec<String> = cells_of(row);
        for index in 0..cells.len() {
            widths[index] = max(widths[index], visible_width(cells[index].clone()));
        }
    }

    widths = fit_widths(widths.clone());

    // Unicode box drawing only where it is known to render; ASCII everywhere else.
    let edges: TableEdges =
        if STYLED.load(Ordering::Relaxed) {
            styled_edges()
        } else {
            plain_edges()
        };

    let mut lines: Vec<String> = vec![style(BOLD, &title)];
    lines.push(
        style(
            GREY,
            &border_line(
                widths.clone(),
                edges.top_left.clone(),
                edges.top_mid.clone(),
                edges.top_right.clone(),
                edges.fill.clone(),
            ),
        ),
    );

    let mut styled_headers: Vec<String> = vec![];
    for header in headers.iter() {
        styled_headers.push(style(BOLD, &header.clone()));
    }

    lines.push(cell_line(styled_headers.clone(), widths.clone(), edges.vertical.clone()));
    lines.push(
        style(
            GREY,
            &border_line(
                widths.clone(),
                edges.mid_left.clone(),
                edges.mid_mid.clone(),
                edges.mid_right.clone(),
                edges.fill.clone(),
            ),
        ),
    );

    for row in rows.iter() {
        lines.push(cell_line(cells_of(row), widths.clone(), edges.vertical.clone()));
    }

    lines.push(
        style(
            GREY,
            &border_line(
                widths.clone(),
                edges.bot_left.clone(),
                edges.bot_mid.clone(),
                edges.bot_right.clone(),
                edges.fill.clone(),
            ),
        ),
    );

    lines.join("\n")
}

pub fn render_summary(title: String, rows: Vec<SummaryRow>) {
    println!("{}", format_summary(title, rows));
}

#[cfg(test)]
#[test]
fn test_level_names() -> anyhow::Result<()> {
    anyhow::ensure!(
        parse_level_name("DEBUG") == Some(LevelFilter::Debug),
        "parse_level_name must be case insensitive"
    );

    anyhow::ensure!(
        parse_level_name("nope").is_none(),
        "unknown level names must not resolve"
    );

    anyhow::ensure!(
        parse_rust_log("warn,my_module=trace") == Some(LevelFilter::Trace),
        "the loudest level in a rust-log style spec must win"
    );

    anyhow::ensure!(
        parse_rust_log("garbage").is_none(),
        "a spec without any level must not resolve"
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_level_precedence() -> anyhow::Result<()> {
    let overridden: InitOptions = InitOptions {
        verbosity: 3,
        quiet: false,
        color: ColorMode::Never,
        plain: false,
        log_level: Some("error".to_string()),
    };

    anyhow::ensure!(
        resolve_level(overridden) == LevelFilter::Error,
        "--log-level must win over the -v count"
    );

    let verbose: InitOptions = InitOptions {
        verbosity: 2,
        quiet: false,
        color: ColorMode::Never,
        plain: false,
        log_level: None,
    };

    anyhow::ensure!(
        resolve_level(verbose) == LevelFilter::Debug,
        "-vv must map to debug",
    );

    let quiet: InitOptions = InitOptions {
        verbosity: 3,
        quiet: true,
        color: ColorMode::Never,
        plain: false,
        log_level: None,
    };

    anyhow::ensure!(
        resolve_level(quiet) == LevelFilter::Error,
        "-q must win over the -v count",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_summary_table() -> anyhow::Result<()> {
    let rows: Vec<SummaryRow> = vec![
        SummaryRow {
            name: "zlib".to_string(),
            version: "1.3.2".to_string(),
            tag: "v1.3.2".to_string(),
            commit: "".to_string(),
            status: "ok".to_string(),
        },
        SummaryRow {
            name: "curl".to_string(),
            version: "7.88.1".to_string(),
            tag: "curl-7_88_1".to_string(),
            commit: "".to_string(),
            status: "dirty".to_string(),
        },
    ];

    let text: String = format_summary("Resolved dependencies".to_string(), rows);
    let lines: Vec<&str> = text.split('\n').collect::<Vec<&str>>();

    anyhow::ensure!(
        lines.len() == 7,
        "expected a title, two rules, a header, a separator and one line per row, got: {text}",
    );

    anyhow::ensure!(
        lines[1].starts_with("+") && lines[1].ends_with("+"),
        "the table must be boxed: {text}",
    );

    anyhow::ensure!(
        lines[2].contains("package") && lines[2].contains("status"),
        "header must come after the top rule: {text}",
    );

    anyhow::ensure!(
        lines[2].find("commit") == None,
        "a column with no data anywhere must not be drawn: {text}",
    );

    anyhow::ensure!(
        lines[6].starts_with("+") && lines[6].ends_with("+"),
        "the table must be closed: {text}",
    );

    anyhow::ensure!(
        lines[5].contains("curl") && lines[5].contains("dirty"),
        "rows must be padded to the widest cell: {text}",
    );

    let first: usize = visible_width(lines[1].to_string());
    anyhow::ensure!(
        lines.iter().skip(1).all(|line: &&str| visible_width(line.to_string()) == first),
        "every table line must be the same width: {text}",
    );

    Ok(())
}

#[cfg(test)]
#[test]
fn test_error_text_chain() -> anyhow::Result<()> {
    use anyhow::Context;

    let failed: anyhow::Result<String> = Err(anyhow::anyhow!("inner cause"));
    let wrapped: anyhow::Result<String> = failed.context("outer message");

    if let Err(e) = &wrapped {
        let text: String = error_text(&e);

        anyhow::ensure!(
            text.contains("inner cause") && text.contains("outer message"),
            "error_text must report the whole cause chain: {text}"
        );

        return Ok(());
    }

    anyhow::bail!("expected the wrapped result to be an error")
}

#[cfg(test)]
#[test]
fn test_summary_cell_cutting() -> anyhow::Result<()> {
    let rows: &[SummaryRow] = &[
        SummaryRow {
            name: "curl".to_string(),
            version: "".to_string(),
            tag: "".to_string(),
            commit: "046209e561b7e9b5aab1aef7daebf29ee6c1b2f4".to_string(),
            status: "dirty".to_string(),
        },
        SummaryRow {
            name: "zlib".to_string(),
            version: "".to_string(),
            tag: "".to_string(),
            commit: "e6d1f4ba39a4b4f79f4a1f1f1f1f1f1f1f1f1f1f".to_string(),
            status: "ok".to_string(),
        },
    ];

    // `sync` pins commits: no semver, no tag, so both columns must be dropped even though
    // every cell is styled and therefore never literally empty.
    let keep: Vec<bool> = keep_columns(rows);
    anyhow::ensure!(
        keep == vec![true, false, false, true, true],
        "empty columns must be decided from the raw fields: {:?}",
        keep,
    );

    // A cut cell must close its colour run, otherwise the padding and the table border
    // inherit the cell's colour.
    // Built explicitly: style() is a no-op when STYLED is off, and the cut has to be
    // exercised on a cell that really carries an escape.
    let cell: String = format!("{}{}{}", GREY, "046209e561b7e9b5aab1aef7daebf29ee6c1b2f4", RESET);
    let cut: String = truncate_visible(cell.clone(), 12);

    anyhow::ensure!(
        visible_width(cut.clone()) == 12 && cut.ends_with(RESET),
        "a truncated cell must end on a closed style: {cut}",
    );

    // Display width, not code point count: combining marks are free, a CJK glyph is wide.
    anyhow::ensure!(
        visible_width("émö亝".to_string()) == 5,
        "visible_width must count display columns, not code points",
    );

    Ok(())
}
