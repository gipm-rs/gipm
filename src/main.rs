use clap::{Parser, ValueEnum};
use gipm::*;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // Command may be clean, sync, or update
    command: Command,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,
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
pub fn main() -> anyhow::Result<()> {
    let parsed_args = Args::parse();
    let cmd = &parsed_args.command;
    match cmd {
        Command::Update => install_dependencies(),
        Command::Sync => sync_dependencies(),
        Command::Clean => clean(),
    }
}
