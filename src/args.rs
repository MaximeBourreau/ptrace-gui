use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "ptrace-gui")]
pub struct Args {
    // A "raw" mode, displaying all syscalls
    #[arg(long)]
    pub raw: bool,
    // The executable to be traced with its arguments
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(external_subcommand)]
    External(Vec<String>),
}
