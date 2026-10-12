use clap::{Parser, ValueEnum};
use gipm::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Command may be clean, sync, or update
    command: Command,

    #[arg(short, long, action = clap::ArgAction::Count)]
    /// Raise the log level: default info, -v debug, -vv trace
    verbose: u8,

    #[arg(short, long, default_value_t = false)]
    /// Only report warnings and errors
    quiet: bool,

    #[arg(long)]
    /// Explicit log level (off, error, warn, info, debug, trace)
    log_level: Option<String>,

    #[arg(long, value_enum, default_value_t = ColorChoice::Auto)]
    /// Colour policy for logs and results
    color: ColorChoice,

    #[arg(long, default_value_t = false)]
    /// Strip colour and cursor control from output
    plain: bool,

    #[arg(long, default_value_t = false)]
    /// Suppress progress bars (logs and summary are still printed)
    no_progress: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Command {
    // Update the dependencies
    Update,
    // Sync dependencies to the .lock file
    Sync,
    // Remove dependencies
    Clean,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ColorChoice {
    // Colour only when the stream is a terminal
    Auto,
    // Always emit colour
    Always,
    // Never emit colour
    Never,
}

fn chosen_color(choice: ColorChoice) -> logging::ColorMode {
    match choice {
        ColorChoice::Auto => logging::ColorMode::Auto,
        ColorChoice::Always => logging::ColorMode::Always,
        ColorChoice::Never => logging::ColorMode::Never,
    }
}

pub fn main() -> anyhow::Result<()> {
    let parsed_args = Args::parse();
    let cmd = &parsed_args.command;

    progress::set_enabled(!parsed_args.no_progress && !parsed_args.quiet && !parsed_args.plain);

    logging::init(logging::InitOptions {
        verbosity: parsed_args.verbose,
        quiet: parsed_args.quiet,
        color: chosen_color(parsed_args.color),
        plain: parsed_args.plain,
        log_level: parsed_args.log_level,
    });

    let outcome: anyhow::Result<()> = match cmd {
        Command::Update => install_dependencies(),
        Command::Sync => sync_dependencies(),
        Command::Clean => clean(),
    };

    if let Err(e) = &outcome {
        // Report the failure through the logging backend (level-tagged, bar-safe) and
        // exit non-zero ourselves; returning the error would let anyhow print the same
        // message a second time, untagged.
        logging::report_error(e);
        logging::flush();
        std::process::exit(1);
    }

    logging::flush();

    Ok(())
}

#[cfg(test)]
#[test]
fn test_chosen_color() -> anyhow::Result<()> {
    anyhow::ensure!(
        chosen_color(ColorChoice::Auto) == logging::ColorMode::Auto,
        "auto must stay auto",
    );
    anyhow::ensure!(
        chosen_color(ColorChoice::Always) == logging::ColorMode::Always,
        "always must stay always",
    );
    anyhow::ensure!(
        chosen_color(ColorChoice::Never) == logging::ColorMode::Never,
        "never must stay never",
    );

    Ok(())
}
