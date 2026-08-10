//! The command-line surface: three flags, and nothing that configures the
//! service.
//!
//! Configuration stays environment-first, because that is how it actually
//! arrives in the two deployments that matter — systemd's `EnvironmentFile=`
//! and a container platform's injected variables. Neither uses a `.env` file,
//! and a flag per setting would be a second way to say everything, which is a
//! second thing to keep in step with `settings.py`.
//!
//! What a flag *is* right for is pointing at an env file, because file
//! discovery is relative to the working directory and a service's working
//! directory is not where anyone thinks it is.
//!
//! Parsed by hand rather than with `clap`: three flags do not justify adding a
//! dependency tree to a binary that holds a signing key, pins every crate by
//! lockfile and audits them on each CI run.

use std::path::PathBuf;

use crate::VERSION;

pub const USAGE: &str = "\
Usage: collateral-provider [OPTIONS]

Serves the collateral-signing API. All configuration comes from the
environment; see sample.env for the full list and the required values.

Options:
      --env-file <PATH>  Load this file into the environment before starting.
                         Without it, a .env file is looked for in the working
                         directory and its parents. Variables already set in
                         the environment always win, so a systemd
                         EnvironmentFile= or a container's own variables are
                         never overridden.
  -h, --help             Print this message and exit.
  -V, --version          Print the version and exit.";

/// What the process was asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Invocation {
    /// Start the server, optionally loading `env_file` first.
    Run { env_file: Option<PathBuf> },
    /// Write this to stdout and exit successfully.
    Print(String),
}

/// Parse the arguments *after* argv[0].
///
/// An unrecognized argument is an error rather than something to ignore. A
/// service that boots anyway after a mistyped flag is a service running a
/// configuration nobody chose — and this one holds a signing key, so the
/// failure mode of guessing is worse than the failure mode of stopping.
pub fn parse<I>(args: I) -> Result<Invocation, String>
where
    I: IntoIterator<Item = String>,
{
    let mut env_file = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Invocation::Print(USAGE.to_string())),
            "-V" | "--version" => {
                return Ok(Invocation::Print(format!("collateral-provider {VERSION}")))
            }
            "--env-file" => {
                let Some(path) = args.next() else {
                    return Err("--env-file requires a path".to_string());
                };
                env_file = Some(PathBuf::from(path));
            }
            // `--env-file=path`, which is the spelling most people try first.
            _ if arg.starts_with("--env-file=") => {
                let path = arg.trim_start_matches("--env-file=");
                if path.is_empty() {
                    return Err("--env-file requires a path".to_string());
                }
                env_file = Some(PathBuf::from(path));
            }
            _ => return Err(format!("unrecognized argument: {arg}")),
        }
    }

    Ok(Invocation::Run { env_file })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Invocation, String> {
        parse(args.iter().map(|arg| (*arg).to_string()))
    }

    fn run_with(args: &[&str]) -> Option<PathBuf> {
        match parse_args(args).expect("parses") {
            Invocation::Run { env_file } => env_file,
            other => panic!("expected a run, got {other:?}"),
        }
    }

    #[test]
    fn no_arguments_runs_with_discovery() {
        assert_eq!(run_with(&[]), None);
    }

    #[test]
    fn both_env_file_spellings_are_accepted() {
        assert_eq!(
            run_with(&["--env-file", "/etc/cp/environment"]),
            Some(PathBuf::from("/etc/cp/environment"))
        );
        assert_eq!(
            run_with(&["--env-file=/etc/cp/environment"]),
            Some(PathBuf::from("/etc/cp/environment"))
        );
        // A path that looks like a flag is still a path.
        assert_eq!(
            run_with(&["--env-file", "--weird"]),
            Some(PathBuf::from("--weird"))
        );
        // Last one wins, as with any repeated option.
        assert_eq!(
            run_with(&["--env-file=a", "--env-file=b"]),
            Some("b".into())
        );
    }

    #[test]
    fn help_and_version_print_and_do_not_run() {
        for flag in ["-h", "--help"] {
            assert_eq!(
                parse_args(&[flag]),
                Ok(Invocation::Print(USAGE.to_string())),
                "{flag}"
            );
        }
        for flag in ["-V", "--version"] {
            assert_eq!(
                parse_args(&[flag]),
                Ok(Invocation::Print(format!("collateral-provider {VERSION}"))),
                "{flag}"
            );
        }
        // The version is the one /healthz and the schema report.
        assert!(USAGE.starts_with("Usage: collateral-provider"));
    }

    /// The whole point: a mistyped flag stops the process instead of booting
    /// a server whose configuration nobody chose.
    #[test]
    fn an_unknown_argument_is_refused_rather_than_ignored() {
        assert_eq!(
            parse_args(&["--enve-file=/etc/cp/environment"]),
            Err("unrecognized argument: --enve-file=/etc/cp/environment".to_string())
        );
        assert_eq!(
            parse_args(&["serve"]),
            Err("unrecognized argument: serve".to_string())
        );
        assert_eq!(
            parse_args(&["--env-file"]),
            Err("--env-file requires a path".to_string())
        );
        assert_eq!(
            parse_args(&["--env-file="]),
            Err("--env-file requires a path".to_string())
        );
        // And it is refused even when a valid flag came first.
        assert_eq!(
            parse_args(&["--env-file=/etc/cp/environment", "--nope"]),
            Err("unrecognized argument: --nope".to_string())
        );
    }
}
