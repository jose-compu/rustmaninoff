//! Parse Kubernetes YAML, including multi-document streams and `List` objects.

use std::path::Path;

use rustmaninoff_ir::{
    extract_skip_comments, lookup, skips_between, skips_from_annotations, Edge, EdgeKind,
    Framework, ParseOutput, Resource, ResourceRef, Value,
};

pub fn parse_file(path: &Path, source: &str) -> ParseOutput {
    let mut output = ParseOutput::default();
    let skips = extract_skip_comments(source);
    for (start_line, document) in split_documents(source) {
        let trimmed = document.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = match serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
            Ok(value) => Value::from_yaml(value),
            Err(err) => {
                output.diagnostics.push(rustmaninoff_ir::Diagnostic {
                    file: path.to_path_buf(),
                    line: start_line,
                    message: err.to_string(),
                });
                continue;
            }
        };
        push_value(path, source, &skips, start_line, parsed, &mut output);
    }
    output
}

fn push_value(
    path: &Path,
    source: &str,
    skips: &[rustmaninoff_ir::LocatedSkip],
    start_line: usize,
    value: Value,
    output: &mut ParseOutput,
) {
    match &value {
        Value::Array(items) => {
            for item in items.clone() {
                push_value(path, source, skips, start_line, item, output);
            }
        }
        Value::Object(_) if value.get("kind").and_then(Value::as_str) == Some("List") => {
            if let Some(Value::Array(items)) = value.get("items").cloned() {
                for item in items {
                    push_value(path, source, skips, start_line, item, output);
                }
            }
        }
        Value::Object(_) => {
            if let Some(resource) = resource_from_object(path, source, skips, start_line, value) {
                collect_k8s_edges(output, &resource);
                output.resources.push(resource);
            }
        }
        _ => {}
    }
}

fn collect_k8s_edges(output: &mut ParseOutput, resource: &Resource) {
    let from = ResourceRef::from_resource(resource);
    if let Some(Value::Array(items)) = resource
        .attributes
        .pointer("metadata.ownerReferences")
        .cloned()
    {
        for item in items {
            let Some(kind) = item.get("kind").and_then(Value::as_str) else {
                continue;
            };
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            output.push_edge(
                Edge::new(from.clone(), ResourceRef::new(kind, name), EdgeKind::Owner)
                    .via("metadata.ownerReferences"),
            );
        }
    }
    let volumes = lookup(&resource.attributes, "_pod_spec.volumes");
    for volume in volumes.values {
        if let Some(claim) = volume
            .pointer("persistentVolumeClaim.claimName")
            .and_then(Value::as_str)
        {
            output.push_edge(
                Edge::new(
                    from.clone(),
                    ResourceRef::new("PersistentVolumeClaim", claim),
                    EdgeKind::Mount,
                )
                .via("spec.volumes"),
            );
        }
    }
}

fn resource_from_object(
    path: &Path,
    source: &str,
    located: &[rustmaninoff_ir::LocatedSkip],
    start_line: usize,
    mut attributes: Value,
) -> Option<Resource> {
    let kind = attributes.get("kind")?.as_str()?.to_string();
    if kind.is_empty() {
        return None;
    }
    let name = attributes
        .pointer("metadata.name")
        .and_then(Value::as_str)
        .unwrap_or("unnamed")
        .to_string();
    let mut skips = skips_between(located, start_line, start_line.saturating_add(200));
    if let Some(metadata) = attributes.get("metadata") {
        skips.extend(skips_from_annotations(metadata));
    }
    if let Some(pod_spec) = pod_spec(&kind, &attributes) {
        let containers = merged_containers(&pod_spec);
        if let Value::Object(map) = &mut attributes {
            map.insert("_pod_spec".to_string(), pod_spec);
            map.insert("_containers".to_string(), containers);
        }
    }
    let end_line = start_line + source[line_byte(source, start_line)..].lines().count();
    Some(Resource {
        framework: Framework::Kubernetes,
        kind: rustmaninoff_ir::ResourceKind::Managed,
        resource_type: kind,
        name,
        attributes,
        file: path.to_path_buf(),
        start_line,
        end_line,
        skips,
    })
}

fn pod_spec(kind: &str, attributes: &Value) -> Option<Value> {
    let path = match kind {
        "Pod" => "spec",
        "Deployment"
        | "StatefulSet"
        | "DaemonSet"
        | "Job"
        | "ReplicaSet"
        | "ReplicationController" => "spec.template.spec",
        "CronJob" => "spec.jobTemplate.spec.template.spec",
        _ => return None,
    };
    lookup(attributes, path).values.first().copied().cloned()
}

fn merged_containers(pod_spec: &Value) -> Value {
    let mut containers = Vec::new();
    for key in ["containers", "initContainers", "ephemeralContainers"] {
        if let Some(Value::Array(items)) = pod_spec.get(key) {
            containers.extend(items.clone());
        }
    }
    Value::Array(containers)
}

fn split_documents(source: &str) -> Vec<(usize, String)> {
    let mut docs = Vec::new();
    let mut start_line = 1usize;
    let mut current = String::new();
    for (line_no, line) in (1usize..).zip(source.split_inclusive('\n')) {
        if line.trim() == "---" && !current.trim().is_empty() {
            docs.push((start_line, std::mem::take(&mut current)));
            start_line = line_no + 1;
        } else if line.trim() == "---" {
            start_line = line_no + 1;
        } else {
            current.push_str(line);
        }
    }
    if !current.trim().is_empty() {
        docs.push((start_line, current));
    }
    docs
}

fn line_byte(source: &str, line: usize) -> usize {
    if line <= 1 {
        return 0;
    }
    source
        .match_indices('\n')
        .nth(line - 2)
        .map(|(index, _)| index + 1)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmaninoff_ir::lookup;

    #[test]
    fn deployment_containers_are_normalized() {
        let source = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: prod
  ownerReferences:
    - kind: ReplicaSet
      name: web-rs
spec:
  template:
    spec:
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: web-data
      containers:
        - name: web
          image: nginx:1.25
          securityContext:
            privileged: true
"#;
        let output = parse_file(Path::new("dep.yaml"), source);
        assert_eq!(output.resources.len(), 1);
        let privileged = lookup(
            &output.resources[0].attributes,
            "_containers.securityContext.privileged",
        );
        assert_eq!(privileged.values[0], &Value::Bool(true));
        assert!(output.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Owner
                && edge.to.resource_type == "ReplicaSet"
                && edge.to.name == "web-rs"
        }));
        assert!(output.edges.iter().any(|edge| {
            edge.kind == EdgeKind::Mount
                && edge.to.resource_type == "PersistentVolumeClaim"
                && edge.to.name == "web-data"
        }));
    }

    #[test]
    fn splits_documents_and_lists() {
        let source = r#"
kind: List
apiVersion: v1
items:
  - kind: Pod
    apiVersion: v1
    metadata:
      name: a
    spec:
      containers:
        - name: a
          image: nginx:1.25
---
kind: Pod
apiVersion: v1
metadata:
  name: b
spec:
  containers:
    - name: b
      image: nginx:1.25
"#;
        let output = parse_file(Path::new("pods.yaml"), source);
        assert_eq!(output.resources.len(), 2, "{:?}", output.diagnostics);
    }
}

#[cfg(test)]
mod coverage;
