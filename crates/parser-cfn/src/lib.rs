//! Parse CloudFormation templates. Attribute paths are relative to `Properties`.

use std::collections::BTreeMap;
use std::path::Path;

use rustmaninoff_ir::{
    extract_skip_comments, skips_between, Framework, ParseOutput, Resource, Value,
};

pub fn parse_file(path: &Path, source: &str) -> ParseOutput {
    let document = if looks_like_json(source) {
        match serde_json::from_str::<serde_json::Value>(source) {
            Ok(value) => Value::from_json(value),
            Err(err) => return fail(path, err.to_string()),
        }
    } else {
        match serde_yaml::from_str::<serde_yaml::Value>(source) {
            Ok(value) => Value::from_yaml(value),
            Err(err) => return fail(path, err.to_string()),
        }
    };
    let document = mark_intrinsics(document);
    let skips = extract_skip_comments(source);
    let Some(resources) = document.get("Resources").and_then(as_object) else {
        return ParseOutput::default();
    };
    let mut output = ParseOutput::default();
    for (name, resource) in resources {
        let Some(resource) = as_object(resource) else {
            continue;
        };
        let Some(type_name) = resource.get("Type").and_then(Value::as_str) else {
            continue;
        };
        let attributes = resource
            .get("Properties")
            .cloned()
            .unwrap_or_else(|| Value::Object(BTreeMap::new()));
        let start_line = find_logical_id_line(source, name);
        output.resources.push(Resource {
            framework: Framework::CloudFormation,
            resource_type: type_name.to_string(),
            name: name.clone(),
            attributes,
            file: path.to_path_buf(),
            start_line,
            end_line: start_line,
            skips: skips_between(&skips, start_line, start_line.saturating_add(40)),
        });
    }
    output
}

fn as_object(value: &Value) -> Option<&BTreeMap<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn looks_like_json(source: &str) -> bool {
    source.trim_start().starts_with('{')
}

fn fail(path: &Path, message: String) -> ParseOutput {
    ParseOutput {
        resources: Vec::new(),
        diagnostics: vec![rustmaninoff_ir::Diagnostic {
            file: path.to_path_buf(),
            line: 1,
            message,
        }],
    }
}

fn mark_intrinsics(value: Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.into_iter().map(mark_intrinsics).collect()),
        Value::Object(map) => {
            if is_intrinsic(&map) {
                let expr = map
                    .keys()
                    .next()
                    .cloned()
                    .unwrap_or_else(|| "intrinsic".into());
                return Value::Unknown { expr };
            }
            Value::Object(
                map.into_iter()
                    .map(|(key, value)| (key, mark_intrinsics(value)))
                    .collect(),
            )
        }
        other => other,
    }
}

fn is_intrinsic(map: &BTreeMap<String, Value>) -> bool {
    if map.len() != 1 {
        return false;
    }
    let key = map.keys().next().map(String::as_str).unwrap_or("");
    key == "Ref" || key.starts_with("Fn::")
}

fn find_logical_id_line(source: &str, name: &str) -> usize {
    let needle = format!("{name}:");
    source
        .lines()
        .position(|line| line.trim_start().starts_with(&needle))
        .map(|index| index + 1)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmaninoff_ir::lookup;

    #[test]
    fn reads_bucket_versioning_and_marks_ref_unknown() {
        let source = r#"
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Logs:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref Name
      VersioningConfiguration:
        Status: Enabled
"#;
        let output = parse_file(Path::new("cfn.yaml"), source);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        assert_eq!(output.resources[0].resource_type, "AWS::S3::Bucket");
        let status = lookup(
            &output.resources[0].attributes,
            "VersioningConfiguration.Status",
        );
        assert_eq!(status.values[0].as_str(), Some("Enabled"));
        let name = lookup(&output.resources[0].attributes, "BucketName");
        assert!(name.unknown);
    }
}

#[cfg(test)]
mod coverage;
