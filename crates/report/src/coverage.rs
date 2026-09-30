use std::path::PathBuf;
use std::sync::Arc;

use rustmaninoff_engine::{Finding, Severity, Status};
use rustmaninoff_ir::Diagnostic;

use super::*;

fn finding(status: Status, severity: Severity, id: &str) -> Finding {
    Finding {
        check_id: Arc::from(id),
        check_name: Arc::from("name"),
        category: Arc::from("GENERAL_SECURITY"),
        severity,
        status,
        resource_address: Arc::from("addr"),
        resource_type: Arc::from("type"),
        resource_name: Arc::from("name"),
        framework: Arc::from("terraform"),
        file: Arc::from("dir\\main.tf"),
        start_line: 1,
        end_line: 2,
        guidelines: Some(Arc::from("https://example.test")),
        skip_reason: Some("because".into()),
    }
}

#[test]
fn text_sarif_and_junit_cover_remaining_labels() {
    let findings = vec![
        finding(Status::Failed, Severity::Medium, "CKV_A"),
        finding(Status::Failed, Severity::Low, "CKV_A"),
        finding(Status::Passed, Severity::High, "CKV_B"),
        finding(Status::Skipped, Severity::High, "CKV_C"),
        finding(Status::Unknown, Severity::High, "CKV_D"),
    ];
    let diagnostics = vec![Diagnostic {
        file: PathBuf::from("main.tf"),
        line: 4,
        message: "bad".into(),
    }];
    let compact = render_text(
        &findings,
        &diagnostics,
        &RenderOptions {
            show_passed: true,
            show_unknown: true,
            compact: true,
        },
    );
    assert!(compact.contains("PARSE_ERROR"));
    assert!(compact.contains("PASSED"));
    assert!(!compact.contains("SKIPPED"));
    let full = render_text(
        &findings,
        &[],
        &RenderOptions {
            show_passed: true,
            show_unknown: true,
            compact: false,
        },
    );
    assert!(full.contains("Skip:"));
    assert!(full.contains("Guide:"));
    assert!(full.contains("UNKNOWN"));
    let hidden = render_text(&findings, &[], &RenderOptions::default());
    assert!(!hidden.contains("UNKNOWN"));
    let sarif = render_sarif(&findings);
    assert!(sarif.contains("warning"));
    assert!(sarif.contains("note"));
    assert!(sarif.contains("dir/main.tf"));
    assert_eq!(sarif.matches("\"id\": \"CKV_A\"").count(), 1);
    let junit = render_junit(&findings, &diagnostics);
    assert!(junit.contains("<skipped/>"));
    let broken = finding(Status::Failed, Severity::High, "CKV\n\r\u{0001}");
    let xml = render_junit(std::slice::from_ref(&broken), &[]);
    assert!(xml.contains("&#10;"));
    assert!(xml.contains("&#13;"));
    assert!(!xml.contains('\u{0001}'));
}
