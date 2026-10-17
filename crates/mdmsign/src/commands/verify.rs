//! `mdmsign verify`

use std::process::ExitCode;

use mdmsign_core::verify::{self, Report, Status, VerifyOptions};

use crate::{
    cli::VerifyArgs,
    output::{self, clean_line},
};

pub fn run(args: VerifyArgs) -> anyhow::Result<ExitCode> {
    let defaults = VerifyOptions::default();
    let options = VerifyOptions {
        offline: args.offline,
        require_notarization: args.require_notarization,
        system_checks: defaults.system_checks && !args.no_system_checks,
    };
    let report = verify::verify_file(&args.file, &options)?;
    if args.json {
        output::print_json(&report)?;
    } else {
        print!("{}", render(&report));
    }
    Ok(if report.mdm_ready {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Renders a report for humans.
pub fn render(report: &Report) -> String {
    // Summaries, details and the signer's name can quote text from the file
    // being verified, which an attacker controls: escape it so it can't fake
    // a "PASS" line or hide a "FAIL" one.
    let mut out = format!(
        "{} ({})\n",
        clean_line(&report.path.display().to_string()),
        report.kind
    );
    if let Some(signer) = &report.signer {
        out.push_str(&format!(
            "  Signed by: {} [{}]\n",
            clean_line(&signer.common_name),
            signer.cert_kind
        ));
        out.push_str(&format!(
            "  Expires:   {}\n",
            signer.not_after.format("%Y-%m-%d")
        ));
    }
    out.push('\n');
    for check in &report.checks {
        let label = match check.status {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Skip => "SKIP",
        };
        out.push_str(&format!("  {label}  {}\n", clean_line(&check.summary)));
        if let Some(detail) = &check.detail {
            for line in detail.lines() {
                out.push_str(&format!("        {}\n", clean_line(line)));
            }
        }
        if let Some(fix) = &check.fix {
            out.push_str(&format!("        fix: {}\n", clean_line(fix)));
        }
    }
    let warnings = report.count(Status::Warn);
    let failures = report.count(Status::Fail);
    out.push('\n');
    if report.mdm_ready {
        let suffix = match warnings {
            0 => String::new(),
            1 => " (1 warning)".into(),
            n => format!(" ({n} warnings)"),
        };
        out.push_str(&format!("Result: PASS: MDM-ready{suffix}\n"));
    } else {
        let plural = if failures == 1 { "" } else { "s" };
        out.push_str(&format!(
            "Result: FAIL: not MDM-ready ({failures} problem{plural})\n"
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use mdmsign_core::{
        ArtifactKind,
        verify::{Check, CheckId},
    };

    use super::*;

    #[test]
    fn renders_summary_and_fixes() {
        let mut report = Report::new(Path::new("app.pkg"), ArtifactKind::FlatPackage);
        report.push(Check::pass(CheckId::SignatureValid, "Signature is valid"));
        report.push(Check::warn(
            CheckId::Notarization,
            "Not notarized",
            "Run `mdmsign notarize app.pkg`.",
        ));
        let text = render(&report.finalize(&VerifyOptions::default()));
        assert!(text.contains("  PASS  Signature is valid"));
        assert!(text.contains("        fix: Run `mdmsign notarize app.pkg`."));
        assert!(
            text.ends_with("Result: PASS: MDM-ready (1 warning)\n"),
            "{text}"
        );
    }

    #[test]
    fn untrusted_text_cannot_fake_lines() {
        let mut report = Report::new(Path::new("app.pkg"), ArtifactKind::FlatPackage);
        report.push(Check::fail(
            CheckId::CertificateChain,
            "Issued by Evil\n  PASS  Certificate is issued by Apple\x1b[8m",
            "Sign it properly.",
        ));
        let text = render(&report.finalize(&VerifyOptions::default()));
        assert!(!text.contains('\x1b'), "{text}");
        assert!(!text.contains("\n  PASS"), "{text}");
        assert!(text.contains("Result: FAIL"), "{text}");
    }
}
