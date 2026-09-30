use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rustmaninoff_engine::Status;
use rustmaninoff_ir::Framework;

use crate::{scan, ScanRequest, Severity};

fn request(path: std::path::PathBuf) -> ScanRequest {
    ScanRequest {
        path,
        frameworks: vec![
            Framework::Terraform,
            Framework::CloudFormation,
            Framework::Kubernetes,
        ],
        checks: vec!["CKV_AWS_3".into()],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        show_unknown: false,
        show_passed: false,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    }
}

fn temp_dir(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-{label}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn oversized_file_is_skipped_without_a_parse_error() {
    let dir = temp_dir("huge");
    let mut file = File::create(dir.join("huge.tf")).unwrap();
    file.write_all(b"resource \"aws_ebs_volume\" \"bad\" {\n")
        .unwrap();
    file.set_len(11_000_000).unwrap();
    let result = scan(&request(dir.clone())).expect("scan");
    println!(
        "oversized diagnostics: {:?}",
        result
            .diagnostics
            .iter()
            .map(|item| item.message.as_str())
            .collect::<Vec<_>>()
    );
    assert!(result
        .diagnostics
        .iter()
        .any(|item| item.message.contains("10MB")));
    assert!(result
        .findings
        .iter()
        .all(|finding| finding.status != Status::Failed));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn deeply_nested_file_is_rejected() {
    let dir = temp_dir("deep");
    let mut source = String::from("resource \"aws_ebs_volume\" \"bad\" {\n");
    source.push_str(&"{".repeat(200));
    source.push_str("\n}\n");
    fs::write(dir.join("deep.tf"), source).unwrap();
    let result = scan(&request(dir.clone())).expect("scan");
    println!(
        "nesting diagnostics: {:?}",
        result
            .diagnostics
            .iter()
            .map(|item| item.message.as_str())
            .collect::<Vec<_>>()
    );
    assert!(result
        .diagnostics
        .iter()
        .any(|item| item.message.contains("safety limit")));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(unix)]
#[test]
fn symlinks_are_not_followed() {
    let dir = temp_dir("link");
    let outside = temp_dir("outside");
    fs::write(
        outside.join("secret.tf"),
        "resource \"aws_ebs_volume\" \"bad\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    std::os::unix::fs::symlink(outside.join("secret.tf"), dir.join("secret.tf")).unwrap();
    let linked_dir = dir.join("elsewhere");
    std::os::unix::fs::symlink(&outside, &linked_dir).unwrap();
    let result = scan(&request(dir.clone())).expect("scan");
    println!(
        "symlink findings: {:?}",
        result
            .findings
            .iter()
            .map(|finding| finding.check_id.as_ref())
            .collect::<Vec<_>>()
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.status != Status::Failed),
        "symlink target was scanned"
    );
    assert!(!result
        .diagnostics
        .iter()
        .any(|item| item.file.ends_with("secret.tf") && !item.message.contains("safety")));
    let _ = fs::remove_dir_all(dir);
    let _ = fs::remove_dir_all(outside);
}

#[test]
fn real_resource_file_is_still_scanned() {
    let dir = temp_dir("real");
    fs::write(
        dir.join("main.tf"),
        "resource \"aws_ebs_volume\" \"bad\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    let result = scan(&request(dir.clone())).expect("scan");
    assert!(result.findings.iter().any(
        |finding| finding.check_id.as_ref() == "CKV_AWS_3" && finding.status == Status::Failed
    ));
    let _ = fs::remove_dir_all(Path::new(&dir));
}
