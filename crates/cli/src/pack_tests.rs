use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rustmaninoff_engine::{Severity, Status};
use rustmaninoff_ir::Framework;
use rustmaninoff_report::{render_json, render_junit, render_sarif, render_text, RenderOptions};

use crate::{builtin_policies, scan, ScanRequest};

#[test]
fn builtin_pack_covers_at_least_160_policies_with_fixtures() {
    let policies = builtin_policies().expect("embedded policies");
    println!("builtin policies: {}", policies.len());
    assert!(
        policies.len() >= 160,
        "expected at least 160 builtin policies, found {}",
        policies.len()
    );
    for policy in &policies {
        let fixtures = policy
            .fixtures
            .as_ref()
            .unwrap_or_else(|| panic!("{} is missing fixtures", policy.id));
        let related: Vec<_> = policies
            .iter()
            .filter(|item| item.id == policy.id && item.framework == policy.framework)
            .cloned()
            .collect();
        println!(
            "check {} {}",
            policy.framework.map(|item| item.as_str()).unwrap_or("any"),
            policy.id
        );
        assert_fixture(policy, &related, &fixtures.fail, true);
        assert_fixture(policy, &related, &fixtures.pass, false);
    }
}

fn assert_fixture(
    policy: &rustmaninoff_engine::Policy,
    related: &[rustmaninoff_engine::Policy],
    source: &str,
    expect_fail: bool,
) {
    let framework = policy.framework.expect("framework");
    let name = match framework {
        Framework::Terraform => "fixture.tf",
        Framework::CloudFormation => "fixture.yaml",
        Framework::Kubernetes => "fixture.yaml",
    };
    let output = match framework {
        Framework::Terraform => rustmaninoff_parser_terraform::parse_file(Path::new(name), source),
        Framework::CloudFormation => rustmaninoff_parser_cfn::parse_file(Path::new(name), source),
        Framework::Kubernetes => rustmaninoff_parser_k8s::parse_file(Path::new(name), source),
    };
    assert!(
        output.diagnostics.is_empty(),
        "{} fixture parse error: {:?} source:\n{source}",
        policy.id,
        output.diagnostics
    );
    assert!(
        !output.resources.is_empty(),
        "{} fixture produced no resources:\n{source}",
        policy.id
    );
    let findings = rustmaninoff_engine::evaluate(&output.resources, related);
    let matched: Vec<_> = findings
        .iter()
        .filter(|finding| finding.check_id == policy.id)
        .collect();
    if expect_fail {
        assert!(
            matched
                .iter()
                .any(|finding| finding.status == Status::Failed),
            "{} fail fixture did not fail. statuses={:?}\n{source}",
            policy.id,
            matched
                .iter()
                .map(|finding| finding.status)
                .collect::<Vec<_>>()
        );
    } else {
        assert!(
            matched
                .iter()
                .any(|finding| finding.status == Status::Passed)
                || !output.resources.iter().any(|resource| {
                    policy
                        .resource_types
                        .iter()
                        .any(|resource_type| resource_type == &resource.resource_type)
                }),
            "{} pass fixture produced no passed result. statuses={:?}\n{source}",
            policy.id,
            matched
                .iter()
                .map(|finding| finding.status)
                .collect::<Vec<_>>()
        );
        assert!(
            matched
                .iter()
                .all(|finding| finding.status == Status::Passed),
            "{} pass fixture statuses={:?}\n{source}",
            policy.id,
            matched
                .iter()
                .map(|finding| finding.status)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn scan_reports_text_json_sarif_and_junit() {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-scan-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("main.tf"),
        r#"
resource "aws_ebs_volume" "bad" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = false
}
"#,
    )
    .unwrap();
    fs::write(
        dir.join("broken.tf"),
        "resource \"aws_ebs_volume\" \"bad\" {\n",
    )
    .unwrap();
    let request = ScanRequest {
        path: dir.clone(),
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
        show_passed: true,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    };
    let result = scan(&request).expect("scan");
    assert_eq!(result.exit_code, 1);
    assert!(result
        .diagnostics
        .iter()
        .any(|item| item.file.ends_with("broken.tf")));
    assert!(result.findings.iter().any(
        |finding| finding.check_id.as_ref() == "CKV_AWS_3" && finding.status == Status::Failed
    ));
    let options = RenderOptions {
        show_passed: true,
        show_unknown: false,
        compact: false,
    };
    let text = render_text(&result.findings, &result.diagnostics, &options);
    let json = render_json(&result.findings, &result.diagnostics);
    let sarif = render_sarif(&result.findings);
    let junit = render_junit(&result.findings, &result.diagnostics);
    println!("{text}");
    assert!(text.contains("FAILED"));
    assert!(text.contains("CKV_AWS_3"));
    assert!(json.contains("\"failed_checks\""));
    assert!(sarif.contains("\"version\": \"2.1.0\""));
    assert!(junit.contains("<testsuite"));
    assert!(junit.contains("<failure"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn skip_comment_suppresses_a_failure() {
    let source = r#"
# checkov:skip=CKV_AWS_3:development volume
resource "aws_ebs_volume" "bad" {
  encrypted = false
}
"#;
    let output = rustmaninoff_parser_terraform::parse_file(Path::new("skipped.tf"), source);
    let policies = builtin_policies().unwrap();
    let related: Vec<_> = policies
        .into_iter()
        .filter(|policy| {
            policy.id.as_ref() == "CKV_AWS_3" && policy.framework == Some(Framework::Terraform)
        })
        .collect();
    let findings = rustmaninoff_engine::evaluate(&output.resources, &related);
    assert!(
        findings
            .iter()
            .any(|finding| finding.status == Status::Skipped),
        "{findings:?}"
    );
    assert!(findings
        .iter()
        .all(|finding| finding.status != Status::Failed));
}
