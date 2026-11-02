//! Parse CloudFormation templates. Attribute paths are relative to `Properties`.

use std::collections::BTreeMap;
use std::path::Path;

use rustmaninoff_ir::{
    extract_skip_comments, skips_between, Edge, EdgeKind, Framework, ParseOutput, Resource,
    ResourceRef, Value,
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
        let from = ResourceRef::new(type_name, name.clone()).with_file(path.to_path_buf());
        collect_depends_on(&mut output, &from, resource.get("DependsOn"));
        let raw_attributes = resource
            .get("Properties")
            .cloned()
            .unwrap_or_else(|| Value::Object(BTreeMap::new()));
        collect_intrinsic_edges(&mut output, &from, None, &raw_attributes);
        let attributes = mark_intrinsics(raw_attributes);
        let start_line = find_logical_id_line(source, name);
        output.resources.push(Resource {
            framework: Framework::CloudFormation,
            kind: rustmaninoff_ir::ResourceKind::Managed,
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

fn collect_depends_on(output: &mut ParseOutput, from: &ResourceRef, value: Option<&Value>) {
    let Some(value) = value else {
        return;
    };
    match value {
        Value::String(name) => {
            output.push_edge(Edge::new(
                from.clone(),
                ResourceRef::new(String::new(), name.clone()),
                EdgeKind::DependsOn,
            ));
        }
        Value::Array(items) => {
            for item in items {
                if let Some(name) = item.as_str() {
                    output.push_edge(Edge::new(
                        from.clone(),
                        ResourceRef::new(String::new(), name.to_string()),
                        EdgeKind::DependsOn,
                    ));
                }
            }
        }
        _ => {}
    }
}

fn collect_intrinsic_edges(
    output: &mut ParseOutput,
    from: &ResourceRef,
    via: Option<&str>,
    value: &Value,
) {
    match value {
        Value::Array(items) => {
            for item in items {
                collect_intrinsic_edges(output, from, via, item);
            }
        }
        Value::Object(map) => {
            if let Some(target) = ref_target(map) {
                let mut edge = Edge::new(from.clone(), target, EdgeKind::Ref);
                if let Some(path) = via {
                    edge = edge.via(path);
                }
                output.push_edge(edge);
                return;
            }
            if let Some(target) = get_att_target(map) {
                let mut edge = Edge::new(from.clone(), target, EdgeKind::GetAtt);
                if let Some(path) = via {
                    edge = edge.via(path);
                }
                output.push_edge(edge);
                return;
            }
            for (key, child) in map {
                collect_intrinsic_edges(output, from, Some(key.as_str()), child);
            }
        }
        _ => {}
    }
}

fn ref_target(map: &BTreeMap<String, Value>) -> Option<ResourceRef> {
    if map.len() != 1 {
        return None;
    }
    let name = map.get("Ref")?.as_str()?;
    Some(ResourceRef::new(String::new(), name.to_string()))
}

fn get_att_target(map: &BTreeMap<String, Value>) -> Option<ResourceRef> {
    if map.len() != 1 {
        return None;
    }
    let value = map.get("Fn::GetAtt")?;
    match value {
        Value::String(text) => {
            let logical = text.split('.').next().unwrap_or(text);
            Some(ResourceRef::new(String::new(), logical.to_string()))
        }
        Value::Array(items) => {
            let logical = items.first()?.as_str()?;
            Some(ResourceRef::new(String::new(), logical.to_string()))
        }
        _ => None,
    }
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
        edges: Vec::new(),
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
  Name:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: logs
  App:
    Type: AWS::S3::Bucket
    DependsOn:
      - Name
    Properties:
      BucketName:
        Ref: Name
      LoggingConfiguration:
        DestinationBucketName:
          Fn::GetAtt:
            - Name
            - Arn
      VersioningConfiguration:
        Status: Enabled
"#;
        let output = parse_file(Path::new("cfn.yaml"), source);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        let app = output
            .resources
            .iter()
            .find(|item| item.name == "App")
            .expect("App");
        assert_eq!(app.resource_type, "AWS::S3::Bucket");
        let status = lookup(&app.attributes, "VersioningConfiguration.Status");
        assert_eq!(status.values[0].as_str(), Some("Enabled"));
        let name = lookup(&app.attributes, "BucketName");
        assert!(name.unknown);
        assert!(output.edges.iter().any(|edge| {
            edge.kind == EdgeKind::DependsOn && edge.from.name == "App" && edge.to.name == "Name"
        }));
        assert!(output.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Ref && edge.from.name == "App" && edge.to.name == "Name"
        }));
        assert!(output.edges.iter().any(|edge| {
            edge.kind == EdgeKind::GetAtt && edge.from.name == "App" && edge.to.name == "Name"
        }));
    }
}

#[cfg(test)]
mod coverage;
