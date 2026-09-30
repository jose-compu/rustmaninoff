use std::collections::BTreeMap;
use std::path::PathBuf;

use rustmaninoff_ir::{Framework, Resource, Skip, Value};

use super::{evaluate, parse_policy, Severity, Status};

fn resource(framework: Framework, resource_type: &str, attrs: serde_json::Value) -> Resource {
    Resource {
        framework,
        resource_type: resource_type.into(),
        name: "n".into(),
        attributes: Value::from_json(attrs),
        file: PathBuf::from("main.tf"),
        start_line: 1,
        end_line: 3,
        skips: Vec::new(),
    }
}

fn status_of(definition: &str, attrs: serde_json::Value) -> Status {
    let policy = parse_policy(&format!(
        "metadata:\n  id: T\n  name: t\n  framework: terraform\nresource_types: [aws_x]\ndefinition:\n{definition}\n"
    ))
    .unwrap_or_else(|err| panic!("{err}\n{definition}"));
    evaluate(&[resource(Framework::Terraform, "aws_x", attrs)], &[policy])
        .first()
        .map(|finding| finding.status)
        .unwrap_or_else(|| panic!("no finding for {definition}"))
}

#[test]
fn operators_cover_pass_fail_and_missing() {
    let cases = [
        ("  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: true", r#"{"a":"true"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: \"2\"", r#"{"a":2}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_equals\n  value: 1", r#"{"a":2}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_equals\n  value: 1", r#"{}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals_any\n  value: [1]", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals_any\n  value: [1]", r#"{"a":[2]}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: exists", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: exists", r#"{}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_exists", r#"{}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_exists", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: contains\n  value: \"bc\"", r#"{"a":"abcd"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: contains\n  value: \"z\"", r#"{"a":["z","y"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_contains\n  value: \"z\"", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: within\n  value: [1, 2]", r#"{"a":[1,2]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: within\n  value: 1", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_within\n  value: [1]", r#"{"a":2}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: regex_match\n  value: \"^a+$\"", r#"{"a":"aaa"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: regex_match\n  value: \"^a+$\"", r#"{"a":["a","aa"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_regex_match\n  value: \"^a+$\"", r#"{"a":"b"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: starting_with\n  value: \"ab\"", r#"{"a":"abcd"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_starting_with\n  value: \"z\"", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: ending_with\n  value: \"cd\"", r#"{"a":"abcd"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_ending_with\n  value: \"z\"", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: greater_than\n  value: 1", r#"{"a":2}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: greater_than_or_equal\n  value: 2", r#"{"a":"2"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: less_than\n  value: 3", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: less_than_or_equal\n  value: 1", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_empty", r#"{"a":""}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_empty", r#"{"a":[]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_empty", r#"{"a":{}}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_not_empty", r#"{"a":"x"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_true", r#"{"a":"true"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_false", r#"{"a":false}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_equals\n  value: 2", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_greater_than\n  value: 1", r#"{"a":["x","y"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_greater_than_or_equal\n  value: 1", r#"{"a":{"k":1}}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_less_than\n  value: 3", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_less_than_or_equal\n  value: 2", r#"{"a":"ab"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: intersects\n  value: [\"s3:Get\"]", r#"{"a":["s3:Get"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: intersects\n  value: [\"s3:Get\"]", r#"{"a":"*"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: not_intersects\n  value: [\"s3:Get\"]", r#"{"a":["ec2:*"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: any", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: image_tag_pinned", r#"{"a":"nginx:1.2"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: image_tag_pinned", r#"{"a":"nginx@sha256:abc"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: image_tag_pinned", r#"{"a":"nginx:latest"}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: image_tag_pinned", r#"{"a":"nginx"}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: missing\n  operator: equals\n  value: 1\n  missing: pass", r#"{}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: missing\n  operator: equals\n  value: 1\n  missing: unknown", r#"{}"#, Status::Unknown),
        ("  cond_type: forbid_resource", r#"{}"#, Status::Failed),
    ];
    for (definition, attrs, expected) in cases {
        let attrs = serde_json::from_str(attrs).unwrap();
        assert_eq!(status_of(definition, attrs), expected, "{definition}");
    }
}

fn status_value(definition: &str, attributes: Value) -> Status {
    let policy = parse_policy(&format!(
        "metadata:\n  id: T\n  name: t\n  framework: terraform\nresource_types: [aws_x]\ndefinition:\n{definition}\n"
    ))
    .unwrap();
    let mut item = resource(Framework::Terraform, "aws_x", serde_json::json!({}));
    item.attributes = attributes;
    evaluate(&[item], &[policy])[0].status
}

fn unknown_attr() -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        "a".into(),
        Value::Unknown {
            expr: "var.a".into(),
        },
    );
    Value::Object(map)
}

#[test]
fn logical_operators_propagate_unknown() {
    let equals_a = "  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: true";
    assert_eq!(status_value(equals_a, unknown_attr()), Status::Unknown);
    assert_eq!(
        status_of(
            "  and:\n    - cond_type: attribute\n      attribute: a\n      operator: equals\n      value: true",
            serde_json::json!({"a": false})
        ),
        Status::Failed
    );
    assert_eq!(
        status_value(
            "  and:\n    - cond_type: attribute\n      attribute: a\n      operator: equals\n      value: true\n    - cond_type: attribute\n      attribute: b\n      operator: equals\n      value: true",
            {
                let mut map = BTreeMap::new();
                map.insert("a".into(), Value::Bool(true));
                map.insert("b".into(), Value::Unknown { expr: "var.b".into() });
                Value::Object(map)
            }
        ),
        Status::Unknown
    );
    assert_eq!(
        status_of(
            "  or:\n    - cond_type: attribute\n      attribute: a\n      operator: equals\n      value: true",
            serde_json::json!({"a": true})
        ),
        Status::Passed
    );
    assert_eq!(
        status_value(
            "  or:\n    - cond_type: attribute\n      attribute: a\n      operator: equals\n      value: false",
            unknown_attr()
        ),
        Status::Unknown
    );
    assert_eq!(
        status_of(
            "  not:\n    cond_type: attribute\n    attribute: a\n    operator: equals\n    value: true",
            serde_json::json!({"a": false})
        ),
        Status::Passed
    );
    assert_eq!(status_value("  not:\n    cond_type: attribute\n    attribute: a\n    operator: equals\n    value: true", unknown_attr()), Status::Unknown);
    assert_eq!(
        status_of("  and: []", serde_json::json!({})),
        Status::Passed
    );
    assert_eq!(status_of("  or: []", serde_json::json!({})), Status::Failed);
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: a\n  operator: exists",
            unknown_attr()
        ),
        Status::Unknown
    );
    let huge = "a".repeat(1_025);
    let oversized = parse_policy(&format!(
        "metadata:\n  id: T\n  name: t\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: regex_match\n  value: \"{huge}\"\n"
    ))
    .unwrap();
    let failed = evaluate(
        &[resource(
            Framework::Terraform,
            "aws_x",
            serde_json::json!({"a": "aaa"}),
        )],
        &[oversized],
    );
    assert_eq!(failed[0].status, Status::Failed);
    assert!(parse_policy("metadata:\n  id: T\n  name: t\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n  missing: later\n").is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\nresource_types: [aws_x]\ndefinition:\n  cond_type: no_element\n  attribute: ingress\n").is_err());
}

#[test]
fn no_element_and_invalid_policies() {
    let clean = status_of(
        "  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22",
        serde_json::json!({"ingress": [{"port": 443}]}),
    );
    assert_eq!(clean, Status::Passed);
    let open = status_of(
        "  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22",
        serde_json::json!({"ingress": [{"port": 22}]}),
    );
    assert_eq!(open, Status::Failed);
    assert!(parse_policy("[]").is_err());
    assert!(parse_policy(
        "metadata:\n  id: T\n  name: t\ndefinition:\n  cond_type: attribute\n  operator: equals\n"
    )
    .is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\n  framework: nope\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n").is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\n  severity: nope\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n").is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\nresource_types: [aws_x]\ndefinition:\n  cond_type: no_such\n").is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\ndefinition: []\n").is_err());
    let mixed_types = parse_policy(
        "metadata:\n  id: T\n  name: t\ndefinition:\n  resource_types: [1, aws_x]\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n",
    )
    .unwrap();
    assert_eq!(mixed_types.resource_types, vec!["aws_x".to_string()]);
    assert!(parse_policy("metadata:\n  id: T\n  name: t\ndefinition:\n  resource_types: 1\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n").is_err());
    assert!(parse_policy("metadata:\n  id: T\n  name: t\ndefinition:\n  and: 1\n").is_err());
    let medium = parse_policy("metadata:\n  id: T\n  name: t\nresource_types: one\ndefinition:\n  resource_types: [aws_x]\n  cond_type: attribute\n  attribute: a\n  operator: no_such\n  value: 1\n");
    assert!(medium.is_err());
    let from_definition = parse_policy(
        "metadata:\n  id: T\n  name: t\n  severity: info\ndefinition:\n  resource_types: aws_x\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n",
    )
    .unwrap();
    assert_eq!(from_definition.severity, Severity::Low);
    assert_eq!(from_definition.resource_types, vec!["aws_x".to_string()]);
    assert!(format!("{}", Severity::Critical).contains("CRITICAL"));
    assert_eq!(Severity::parse("med"), Some(Severity::Medium));
    assert_eq!(Severity::parse("crit"), Some(Severity::Critical));
    assert!(Severity::parse("nope").is_none());
}

#[test]
fn index_covers_wildcards_unscoped_skip_and_parallel() {
    let wild = parse_policy(
        "metadata:\n  id: W\n  name: w\n  framework: terraform\n  category: NET\n  guidelines: https://example.test\nresource_types: [\"*\", aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n",
    )
    .unwrap();
    let unscoped = parse_policy(
        "metadata:\n  id: U\n  name: u\nresource_types: all\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n",
    )
    .unwrap();
    let mut item = resource(
        Framework::Terraform,
        "aws_other",
        serde_json::json!({"a": 1}),
    );
    item.skips.push(Skip {
        check_id: "W".into(),
        reason: Some("ok".into()),
    });
    let findings = evaluate(&[item], &[wild, unscoped.clone()]);
    assert!(findings
        .iter()
        .any(|finding| finding.check_id.as_ref() == "W" && finding.status == Status::Skipped));
    assert!(findings
        .iter()
        .any(|finding| finding.check_id.as_ref() == "U" && finding.status == Status::Passed));
    assert!(evaluate(&[], std::slice::from_ref(&unscoped)).is_empty());
    let many: Vec<_> = (0..32)
        .map(|index| {
            let mut item = resource(
                Framework::CloudFormation,
                "AWS::S3::Bucket",
                serde_json::json!({"a": 0}),
            );
            item.name = format!("n{index}");
            item
        })
        .collect();
    let cfn = parse_policy(
        "metadata:\n  id: C\n  name: c\n  framework: cloudformation\nresource_types: [AWS::S3::Bucket]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n",
    )
    .unwrap();
    assert_eq!(evaluate(&many, &[cfn]).len(), 32);
}

#[test]
fn load_policy_directory_skips_links_and_rejects_bad_files() {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-policies-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let nested = dir.join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    let body = "metadata:\n  id: EXT\n  name: ext\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n";
    std::fs::write(nested.join("one.yml"), body).unwrap();
    std::fs::write(dir.join("notes.txt"), "ignore").unwrap();
    std::fs::write(dir.join("bad.yaml"), "[]").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(nested.join("one.yml"), dir.join("link.yaml")).unwrap();
    let loaded = super::load_policy_dir(&nested).unwrap();
    assert_eq!(loaded.len(), 1);
    let err = super::load_policy_dir(&dir).unwrap_err();
    assert!(err.to_string().contains("invalid") || err.to_string().contains("bad.yaml"));
    let missing = super::load_policy_dir(PathBuf::from("/no/such/rustmaninoff-policies").as_path());
    assert!(missing.unwrap_err().to_string().contains("failed to read"));
    let huge = dir.join("huge.yaml");
    let mut file = std::fs::File::create(&huge).unwrap();
    use std::io::Write;
    file.write_all(b"metadata:\n").unwrap();
    file.set_len(1_000_001).unwrap();
    drop(file);
    std::fs::remove_file(dir.join("bad.yaml")).unwrap();
    let too_big = super::load_policy_dir(&dir).unwrap_err();
    assert!(too_big.to_string().contains("1MB") || too_big.to_string().contains("huge"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn load_directory_sorts_and_skips_non_policies() {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-policies-clean-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(dir.join("nested")).unwrap();
    let body = |id: &str, framework: &str| {
        format!("metadata:\n  id: {id}\n  name: {id}\n  framework: {framework}\nresource_types: [aws_x]\ndefinition:\n  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 1\n")
    };
    std::fs::write(dir.join("b.yaml"), body("B", "terraform")).unwrap();
    std::fs::write(dir.join("nested/a.yml"), body("A", "kubernetes")).unwrap();
    std::fs::write(dir.join("notes.txt"), "ignore").unwrap();
    std::fs::write(dir.join("Makefile"), "ignore").unwrap();
    #[cfg(unix)]
    {
        let pipe = dir.join("pipe.yaml");
        let _ = std::process::Command::new("mkfifo").arg(&pipe).status();
    }
    std::fs::write(dir.join("deep.yaml"), "{".repeat(200)).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.join("b.yaml"), dir.join("link.yaml")).unwrap();
    let err = super::load_policy_dir(&dir).unwrap_err();
    assert!(err.to_string().contains("nesting") || err.to_string().contains("deep.yaml"));
    std::fs::remove_file(dir.join("deep.yaml")).unwrap();
    let loaded = super::load_policy_dir(&dir).unwrap();
    assert_eq!(loaded.len(), 2);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn operator_edges_and_no_element_unknown() {
    let cases = [
        ("  cond_type: attribute\n  attribute: a\n  operator: not_exists", r#"{"a":{"expr":1}}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: \"true\"", r#"{"a":true}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: contains\n  value: 1", r#"{"a":[[1]]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: contains\n  value: 1", r#"{"a":1}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: within\n  value: [1, 2]", r#"{"a":[1, 3]}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: within", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: starting_with", r#"{"a":"ab"}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: starting_with\n  value: \"a\"", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: greater_than", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_empty", r#"{"a":null}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_empty", r#"{"a":true}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: is_true", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_equals\n  value: 1", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: length_equals", r#"{"a":"ab"}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: intersects", r#"{"a":"s3:Get"}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: intersects\n  value: [1, true]", r#"{"a":["1"]}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: equals\n  value: 2", r#"{"a":"2"}"#, Status::Passed),
        ("  cond_type: attribute\n  attribute: a\n  operator: image_tag_pinned", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: regex_match\n  value: \"^a$\"", r#"{"a":1}"#, Status::Failed),
        ("  cond_type: attribute\n  attribute: a\n  operator: intersects\n  value: {\"k\": \"s3:Get\"}", r#"{"a":"s3:Get"}"#, Status::Failed),
        ("  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22", r#"{"ingress":{"one":{"port":22}}}"#, Status::Failed),
    ];
    for (definition, attrs, expected) in cases {
        let attrs = serde_json::from_str(attrs).unwrap();
        assert_eq!(status_of(definition, attrs), expected, "{definition}");
    }
    let mut mixed = BTreeMap::new();
    mixed.insert(
        "items".into(),
        Value::Array(vec![
            Value::Unknown {
                expr: "var.a".into(),
            },
            Value::Object(BTreeMap::from([("a".into(), Value::Number(1.into()))])),
        ]),
    );
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: items.a\n  operator: equals\n  value: 1",
            Value::Object(mixed)
        ),
        Status::Unknown
    );
    let mut missing = BTreeMap::new();
    missing.insert(
        "items".into(),
        Value::Array(vec![
            Value::Object(BTreeMap::from([("a".into(), Value::Number(1.into()))])),
            Value::Object(BTreeMap::new()),
        ]),
    );
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: items.a\n  operator: equals\n  value: 1",
            Value::Object(missing)
        ),
        Status::Failed
    );
    assert_eq!(
        status_value(
            "  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22",
            unknown_attr_named("ingress")
        ),
        Status::Unknown
    );
    let mut elements = BTreeMap::new();
    elements.insert(
        "ingress".into(),
        Value::Array(vec![
            Value::Unknown {
                expr: "var.r".into(),
            },
            Value::Object(BTreeMap::from([("port".into(), Value::Number(443.into()))])),
        ]),
    );
    assert_eq!(
        status_value(
            "  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22",
            Value::Object(elements)
        ),
        Status::Unknown
    );
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: a\n  operator: not_exists",
            unknown_attr()
        ),
        Status::Unknown
    );
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: items.a\n  operator: exists",
            {
                let mut map = BTreeMap::new();
                map.insert(
                    "items".into(),
                    Value::Array(vec![
                        Value::Object(BTreeMap::from([("a".into(), Value::Number(1.into()))])),
                        Value::Unknown {
                            expr: "var.a".into(),
                        },
                    ]),
                );
                Value::Object(map)
            }
        ),
        Status::Unknown
    );
    assert_eq!(
        status_value(
            "  cond_type: attribute\n  attribute: items.a\n  operator: equals_any\n  value: [1]",
            {
                let mut map = BTreeMap::new();
                map.insert(
                    "items".into(),
                    Value::Array(vec![
                        Value::Unknown {
                            expr: "var.a".into(),
                        },
                        Value::Object(BTreeMap::from([("a".into(), Value::Number(2.into()))])),
                    ]),
                );
                Value::Object(map)
            }
        ),
        Status::Unknown
    );
    let mut port = BTreeMap::new();
    port.insert(
        "port".into(),
        Value::Unknown {
            expr: "var.p".into(),
        },
    );
    assert_eq!(
        status_value(
            "  cond_type: no_element\n  attribute: ingress\n  where:\n    cond_type: attribute\n    attribute: port\n    operator: equals\n    value: 22",
            Value::Object(BTreeMap::from([(
                "ingress".into(),
                Value::Array(vec![Value::Object(port)])
            )]))
        ),
        Status::Unknown
    );
    assert_eq!(
        status_of(
            "  cond_type: no_element\n  attribute: items.port\n  where:\n    cond_type: attribute\n    attribute: .\n    operator: equals\n    value: 22",
            serde_json::json!({"items": [{"port": 80}, {"port": 22}]})
        ),
        Status::Failed
    );
}

fn unknown_attr_named(key: &str) -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        key.into(),
        Value::Unknown {
            expr: "var.x".into(),
        },
    );
    Value::Object(map)
}
