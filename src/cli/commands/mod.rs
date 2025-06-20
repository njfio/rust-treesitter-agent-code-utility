//! CLI command implementations
//! 
//! This module contains the implementation of all CLI commands with proper separation of concerns.

pub mod analyze;
pub mod security;
pub mod refactor;
pub mod dependencies;
pub mod query;
pub mod stats;
pub mod find;
pub mod symbols;
pub mod languages;
pub mod interactive;
pub mod insights;
pub mod map;
pub mod explain;

use super::{Commands, Execute};
use super::error::{CliError, CliResult};

impl Execute for Commands {
    type Error = CliError;
    
    fn execute(&self) -> CliResult<()> {
        match self {
            Commands::Analyze {
                path, format, max_size, max_depth, depth, include_hidden,
                exclude_dirs, include_exts, output, detailed
            } => {
                analyze::execute(
                    path, format, *max_size, *max_depth, depth, *include_hidden,
                    exclude_dirs.as_ref(), include_exts.as_ref(), output.as_ref(), *detailed
                )
            }
            Commands::Query { path, pattern, language, context, format } => {
                query::execute(path, pattern, language, *context, format)
            }
            Commands::Stats { path, top } => {
                stats::execute(path, *top)
            }
            Commands::Find { path, name, symbol_type, language, public_only } => {
                find::execute(path, name.as_ref(), symbol_type.as_ref(), language.as_ref(), *public_only)
            }
            Commands::Symbols { path, format } => {
                symbols::execute(path, format)
            }
            Commands::Languages => {
                languages::execute()
            }
            Commands::Interactive { path } => {
                interactive::execute(path)
            }
            Commands::Insights { path, focus, format } => {
                insights::execute(path, focus, format)
            }
            Commands::Map {
                path, map_type, format, max_depth, show_sizes, show_symbols,
                languages, collapse_empty, depth
            } => {
                map::execute(
                    path, map_type, format, *max_depth, *show_sizes, *show_symbols,
                    languages.as_ref(), *collapse_empty, depth
                )
            }
            Commands::Explain { path, file, symbol, format, detailed, learning } => {
                explain::execute(path, file.as_ref(), symbol.as_ref(), format, *detailed, *learning)
            }
            Commands::Security {
                path, format, min_severity, output, summary_only, compliance, depth
            } => {
                security::execute(
                    path, format, min_severity, output.as_ref(), *summary_only, *compliance, depth
                )
            }
            Commands::Refactor {
                path, category, format, quick_wins, major_only, min_priority, output
            } => {
                refactor::execute(
                    path, category.as_ref(), format, *quick_wins, *major_only, min_priority, output.as_ref()
                )
            }
            Commands::Dependencies {
                path, format, include_dev, vulnerabilities, licenses, outdated, graph, output
            } => {
                dependencies::execute(
                    path, format, *include_dev, *vulnerabilities, *licenses, *outdated, *graph, output.as_ref()
                )
            }
        }
    }
}
