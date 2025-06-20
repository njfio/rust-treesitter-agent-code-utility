//! Smart CLI interface for the rust-tree-sitter library
//! 
//! This CLI provides intelligent codebase analysis, querying, and insights
//! for developers and AI code agents.

use rust_tree_sitter::cli::{Cli, Execute};
use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    if let Err(e) = cli.command.execute() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
    
    Ok(())
}
