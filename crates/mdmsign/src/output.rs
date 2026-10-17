//! Printing results and errors.

use std::{borrow::Cow, process::ExitCode};

use mdmsign_core::Error;

/// Exit status for a usage or credential problem.
pub const EXIT_USAGE: u8 = 2;

/// Prints an error with its causes and a fix, and picks the exit status.
pub fn report_error(err: &anyhow::Error) -> ExitCode {
    // Errors can quote certificate names and tool output from the files
    // being processed, so escape anything that could drive the terminal.
    eprintln!("error: {}", clean(&err.to_string()));
    let mut source = err.source();
    while let Some(cause) = source {
        // Library errors already include their source in the message.
        let text = cause.to_string();
        if !err.to_string().contains(&text) {
            eprintln!("  caused by: {}", clean(&text));
        }
        source = cause.source();
    }

    let core = err.downcast_ref::<Error>();
    if let Some(hint) = core.and_then(Error::hint) {
        let hint = clean(&hint);
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

/// Escapes control characters (terminal escape sequences, carriage returns,
/// bidirectional overrides) in text that may come from an untrusted file,
/// such as a certificate name or a notary log message, so it can't rewrite
/// or hide what's on the screen. Newlines are kept.
pub fn clean(text: &str) -> Cow<'_, str> {
    escape(text, |c| c != '\n' && is_unsafe(c))
}

/// Like [`clean`], but also escapes newlines, for values printed on one line
/// so they can't add lines of their own (e.g. a fake "PASS").
pub fn clean_line(text: &str) -> Cow<'_, str> {
    escape(text, is_unsafe)
}

fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn escape(text: &str, unsafe_char: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text.chars().any(&unsafe_char) {
        return Cow::Borrowed(text);
    }
    Cow::Owned(
        text.chars()
            .map(|c| {
                if unsafe_char(c) {
                    c.escape_default().to_string()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_terminal_controls() {
        assert!(matches!(
            clean("Developer ID Installer: Example"),
            Cow::Borrowed(_)
        ));
        assert_eq!(clean("a\x1b[8mb"), "a\\u{1b}[8mb");
        assert_eq!(clean("one\ntwo\r"), "one\ntwo\\r");
        assert_eq!(clean_line("one\ntwo"), "one\\ntwo");
        assert_eq!(clean_line("abc\u{202e}gpj.exe"), "abc\\u{202e}gpj.exe");
    }
}
