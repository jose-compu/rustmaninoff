//! Render scan results for humans and CI.

use rustmaninoff_engine::{Finding, Severity, Status};
use rustmaninoff_ir::Diagnostic;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, Default)]
pub struct RenderOptions {
    pub show_passed: bool,
    pub show_unknown: bool,
    pub compact: bool,
}

pub fn render_text(
    findings: &[Finding],
    diagnostics: &[Diagnostic],
    options: &RenderOptions,
) -> String {
    let mut out = String::new();
    let failed = count(findings, Status::Failed);
    let passed = count(findings, Status::Passed);
    let skipped = count(findings, Status::Skipped);
    let unknown = count(findings, Status::Unknown);
    out.push_str(&format!(
        "Passed checks: {passed}, Failed checks: {failed}, Skipped checks: {skipped}, Unknown checks: {unknown}, Parse errors: {}\n",
        diagnostics.len()
    ));
    for diagnostic in diagnostics {
        out.push_str(&format!(
            "PARSE_ERROR: {}:{}: {}\n",
            diagnostic.file.display(),
            diagnostic.line,
            diagnostic.message
        ));
    }
    for finding in findings {
        if finding.status == Status::Passed && !options.show_passed {
            continue;
        }
        if finding.status == Status::Unknown && !options.show_unknown {
            continue;
        }
        if finding.status == Status::Skipped && options.compact {
            continue;
        }
        if options.compact {
            out.push_str(&format!(
                "{} {} {} {}:{} {}\n",
                finding.status_label(),
                finding.severity,
                finding.check_id,
                finding.file,
                finding.start_line,
                finding.resource_address
            ));
            continue;
        }
        out.push_str(&format!(
            "\nCheck: {}: \"{}\"\n\t{} for resource: {}\n\tFile: {}:{}-{}\n\tSeverity: {}\n",
            finding.check_id,
            finding.check_name,
            finding.status_label(),
            finding.resource_address,
            finding.file,
            finding.start_line,
            finding.end_line,
            finding.severity
        ));
        if let Some(reason) = &finding.skip_reason {
            out.push_str(&format!("\tSkip: {reason}\n"));
        }
        if let Some(guide) = &finding.guidelines {
            out.push_str(&format!("\tGuide: {guide}\n"));
        }
    }
    out
}

pub fn render_json(findings: &[Finding], diagnostics: &[Diagnostic]) -> String {
    let bucket = |status: Status| {
        findings
            .iter()
            .filter(|finding| finding.status == status)
            .map(finding_json)
            .collect::<Vec<_>>()
    };
    let value = serde_json::json!({
        "tool": "rustmaninoff",
        "version": VERSION,
        "results": {
            "failed_checks": bucket(Status::Failed),
            "passed_checks": bucket(Status::Passed),
            "skipped_checks": bucket(Status::Skipped),
            "unknown_checks": bucket(Status::Unknown),
            "parse_errors": diagnostics.iter().map(|item| serde_json::json!({
                "file": item.file.display().to_string(),
                "line": item.line,
                "message": item.message,
            })).collect::<Vec<_>>(),
        },
        "summary": {
            "failed": count(findings, Status::Failed),
            "passed": count(findings, Status::Passed),
            "skipped": count(findings, Status::Skipped),
            "unknown": count(findings, Status::Unknown),
            "parse_errors": diagnostics.len(),
        }
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

pub fn render_sarif(findings: &[Finding]) -> String {
    let failed: Vec<_> = findings
        .iter()
        .filter(|finding| finding.status == Status::Failed)
        .collect();
    let mut rules = Vec::new();
    let mut seen = Vec::new();
    for finding in &failed {
        if seen.contains(&finding.check_id) {
            continue;
        }
        seen.push(finding.check_id.clone());
        rules.push(serde_json::json!({
            "id": finding.check_id.as_ref(),
            "shortDescription": {"text": finding.check_name.as_ref()},
            "fullDescription": {"text": finding.check_name.as_ref()},
            "defaultConfiguration": {"level": sarif_level(finding.severity)},
            "helpUri": finding.guidelines.as_deref().unwrap_or(""),
        }));
    }
    let results = failed
        .iter()
        .map(|finding| {
            serde_json::json!({
                "ruleId": finding.check_id.as_ref(),
                "level": sarif_level(finding.severity),
                "message": {"text": format!("{} {}", finding.check_name, finding.resource_address)},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": sarif_uri(&finding.file)},
                        "region": {"startLine": finding.start_line.max(1)}
                    }
                }]
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "rustmaninoff",
                    "version": VERSION,
                    "informationUri": "https://github.com/rustmaninoff/rustmaninoff",
                    "rules": rules,
                }
            },
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

pub fn render_junit(findings: &[Finding], diagnostics: &[Diagnostic]) -> String {
    let cases = findings.len() + diagnostics.len();
    let failures = count(findings, Status::Failed) + diagnostics.len();
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<testsuite name=\"rustmaninoff\" tests=\"{cases}\" failures=\"{failures}\">\n"
    ));
    for finding in findings {
        let name = xml_escape(&format!(
            "{} {}",
            finding.check_id, finding.resource_address
        ));
        let classname = xml_escape(&finding.file);
        out.push_str(&format!(
            "  <testcase classname=\"{classname}\" name=\"{name}\">\n"
        ));
        match finding.status {
            Status::Failed => {
                let message = xml_escape(&format!("{} ({})", finding.check_name, finding.severity));
                out.push_str(&format!("    <failure message=\"{message}\"/>\n"));
            }
            Status::Skipped | Status::Unknown => {
                out.push_str("    <skipped/>\n");
            }
            Status::Passed => {}
        }
        out.push_str("  </testcase>\n");
    }
    for diagnostic in diagnostics {
        let name = xml_escape(&format!("PARSE_ERROR {}", diagnostic.file.display()));
        let message = xml_escape(&diagnostic.message);
        out.push_str(&format!(
            "  <testcase classname=\"parse\" name=\"{name}\"><failure message=\"{message}\"/></testcase>\n"
        ));
    }
    out.push_str("</testsuite>\n");
    out
}

fn count(findings: &[Finding], status: Status) -> usize {
    findings
        .iter()
        .filter(|finding| finding.status == status)
        .count()
}

fn finding_json(finding: &Finding) -> serde_json::Value {
    serde_json::json!({
        "check_id": finding.check_id.as_ref(),
        "check_name": finding.check_name.as_ref(),
        "check_result": finding.status_label(),
        "severity": finding.severity.as_str(),
        "resource": finding.resource_address.as_ref(),
        "file_path": finding.file.as_ref(),
        "file_line_range": [finding.start_line, finding.end_line],
        "guideline": finding.guidelines.as_deref(),
        "skip_reason": finding.skip_reason,
        "framework": finding.framework.as_ref(),
    })
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn sarif_uri(path: &str) -> String {
    path.replace('\\', "/")
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

trait StatusLabel {
    fn status_label(&self) -> &'static str;
}

impl StatusLabel for Finding {
    fn status_label(&self) -> &'static str {
        match self.status {
            Status::Passed => "PASSED",
            Status::Failed => "FAILED",
            Status::Skipped => "SKIPPED",
            Status::Unknown => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rustmaninoff_engine::{Finding, Severity, Status};

    use super::render_junit;

    #[test]
    fn junit_escapes_markup_in_attributes() {
        let finding = Finding {
            check_id: Arc::from("CKV\"><script>"),
            check_name: Arc::from("a<b>&\"c"),
            category: Arc::from("GENERAL"),
            severity: Severity::High,
            status: Status::Failed,
            resource_address: Arc::from("aws_ebs_volume.bad"),
            resource_type: Arc::from("aws_ebs_volume"),
            resource_name: Arc::from("bad"),
            framework: Arc::from("terraform"),
            file: Arc::from("main.tf"),
            start_line: 1,
            end_line: 2,
            guidelines: None,
            skip_reason: None,
        };
        let xml = render_junit(std::slice::from_ref(&finding), &[]);
        assert!(xml.contains("&quot;"));
        assert!(xml.contains("&lt;"));
        assert!(xml.contains("&amp;"));
        assert!(!xml.contains("<script>"));
        assert!(!xml.contains("\"><"));
    }
}

#[cfg(test)]
mod coverage;
