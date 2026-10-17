//! Printing results and errors.

use std::process::ExitCode;

use mdmsign_core::Error;

/// Exit status for a usage or credential problem.
pub const EXIT_USAGE: u8 = 2;

/// Prints an error with its causes and a fix, and picks the exit status.
pub fn report_error(err: &anyhow::Error) -> ExitCode {
    eprintln!("error: {err}");
    let mut source = err.source();
    while let Some(cause) = source {
        // Library errors already include their source in the message.
        let text = cause.to_string();
        if !err.to_string().contains(&text) {
            eprintln!("  caused by: {text}");
        }
        source = cause.source();
    }

    let core = err.downcast_ref::<Error>();
    if let Some(hint) = core.and_then(Error::hint) {
        let mut lines = hint.lines();
        if let Some(first) = lines.next() {
            eprintln!("  fix: {first}");
        }
        for line in lines {
            eprintln!("       {line}");
        }
    }
    if core.is_some_and(Error::is_usage_error) {
        ExitCode::from(EXIT_USAGE)
    } else {
        ExitCode::FAILURE
    }
}

/// Prints `value` as pretty JSON on stdout.
pub fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
