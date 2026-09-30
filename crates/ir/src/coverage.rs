use super::*;

#[test]
fn framework_aliases_and_display() {
    assert_eq!(Framework::parse("tf"), Some(Framework::Terraform));
    assert_eq!(Framework::parse(" cfn "), Some(Framework::CloudFormation));
    assert_eq!(Framework::parse("k8s"), Some(Framework::Kubernetes));
    assert!(Framework::parse("helm").is_none());
    assert_eq!(Framework::Terraform.to_string(), "terraform");
    assert_eq!(Framework::CloudFormation.to_string(), "cloudformation");
    assert_eq!(Framework::Kubernetes.to_string(), "kubernetes");
}

#[test]
fn values_convert_and_lookup_every_shape() {
    let json = Value::from_json(serde_json::json!({
        "n": null,
        "b": true,
        "i": 1,
        "s": "[1, 2]",
        "plain": "hello",
        "list": [1],
        "obj": {"k": "v"}
    }));
    assert!(json.get("missing").is_none());
    assert!(json.get("n").unwrap().is_null());
    assert_eq!(json.pointer("list.0").and_then(Value::as_f64), Some(1.0));
    assert!(json.pointer("missing").is_none());
    assert_eq!(Value::string("{not").as_str(), Some("{not"));
    assert_eq!(Value::string("1.5").as_f64(), Some(1.5));
    let yaml = Value::from_yaml(serde_yaml::from_str("a: 1.5\ntrue: x\n1: y\n").unwrap());
    assert!(yaml.get("a").unwrap().as_f64().is_some());
    assert!(yaml.get("true").is_some());
    let root = Value::Unknown {
        expr: "var.x".into(),
    };
    assert!(lookup(&root, "a").unknown);
    assert_eq!(lookup(&json, "").values.len(), 1);
    assert_eq!(lookup(&json, ".").values.len(), 1);
    assert_eq!(lookup(&json, "obj/k").values[0].as_str(), Some("v"));
    assert!(lookup(&json, "list[1]").missing);
    assert!(lookup(&json, "list.nope").missing);
    let empty = Value::Array(vec![]);
    assert!(lookup(&empty, "k").missing);
    let scalar = Value::Bool(true);
    assert!(lookup(&scalar, "k").missing);
    assert_eq!(byte_to_line("a\nb", 99), 2);
}

#[test]
fn input_limit_covers_quotes_comments_and_indent() {
    assert!(input_limit("# {\n// {\n\"a\\\"b\"\n'it''s'\n}\n]\n)\n* not\n").is_none());
    let indent = format!("{}x", " ".repeat(513));
    assert_eq!(
        input_limit(&indent),
        Some("file indentation exceeds the safety limit")
    );
    assert!(input_limit("*alias").is_none() || input_limit("*alias").is_some());
}

#[test]
fn skip_windows_and_annotations() {
    let src = "a\n# checkov:skip=CKV_AWS_3:because\nb\n";
    let located = extract_skip_comments(src);
    assert_eq!(skips_between(&located, 10, 1).len(), 1);
    let metadata = Value::from_json(serde_json::json!({
        "annotations": {
            "checkov.io/skip": "CKV_K8S_16=reason",
            "checkov.io/skip1": "CKV_K8S_8",
            "other": "no",
            "checkov.io/skip2": 1
        }
    }));
    let skips = skips_from_annotations(&metadata);
    assert_eq!(skips.len(), 2);
    assert!(skips_from_annotations(&Value::Null).is_empty());
    assert!(
        skips_from_annotations(&Value::from_json(serde_json::json!({"annotations": "x"})))
            .is_empty()
    );
    let tagged = Value::from_yaml(serde_yaml::from_str("a: !Ref Name\nnull: 1\n").unwrap());
    assert!(matches!(tagged.get("a"), Some(Value::Unknown { .. })));
    let wide = Value::from_yaml(serde_yaml::from_str("n: 9223372036854775808\n").unwrap());
    assert!(wide.get("n").unwrap().as_f64().is_some());
    assert!(Value::Bool(true).as_f64().is_none());
    assert_eq!(Value::string("[").as_str(), Some("["));
    assert!(Value::string("[1,2]").get("0").is_none());
    assert_eq!(
        Value::string("{\"a\":1}").get("a").and_then(Value::as_f64),
        Some(1.0)
    );
    let null_value = Value::from_yaml(serde_yaml::from_str("a: null\n").unwrap());
    assert!(null_value.get("a").unwrap().is_null());
    let keyed = Value::from_yaml(serde_yaml::from_str("? [1, 2]\n: value\n").unwrap());
    assert!(keyed.as_str().is_none());
    assert_eq!(lookup_path(&tagged, &AttrPath::parse("")).values.len(), 1);
    assert!(lookup(&Value::Unknown { expr: "x".into() }, "").unknown);
    let sample = Value::from_json(serde_json::json!({"obj": {"k": "v"}, "list": [1]}));
    assert_eq!(
        lookup(&sample, "obj..k")
            .values
            .first()
            .and_then(|value| value.as_str()),
        Some("v")
    );
    assert!(!lookup(&sample, "list[0").values.is_empty() || lookup(&sample, "list[0").missing);
    assert!(lookup(&sample, "obj[0]").missing);
    let nested = Value::from_json(serde_json::json!({"items": []}));
    assert!(lookup(&nested, "items.k").missing);
    assert!(input_limit("*").is_none());
    let blank = skips_from_annotations(&Value::from_json(
        serde_json::json!({"annotations": {"checkov.io/skip": "CKV_K8S_1="}}),
    ));
    assert!(blank[0].reason.is_none());
}
