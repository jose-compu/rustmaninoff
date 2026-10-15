use std::path::Path;

use rustmaninoff_ir::{lookup, ResourceKind, Value};

use super::*;

#[test]
fn dockerfile_shapes_and_privileged_patterns() {
    let source = r#"
# comment
FROM --platform=linux/amd64 alpine:3.19 AS builder
FROM scratch
FROM nginx@sha256:abc
USER 1000
COPY app /app
RUN apt-get update && \
    apt-get install -y curl
RUN --privileged chmod 777 /tmp
HEALTHCHECK NONE
"#;
    let output = parse_file(Path::new("Dockerfile.app"), source);
    assert_eq!(output.resources[0].kind, ResourceKind::Managed);
    assert_eq!(output.resources[0].resource_type, "dockerfile");
    assert_eq!(output.resources[0].name, "Dockerfile.app");
    let attrs = &output.resources[0].attributes;
    let images = lookup(attrs, "FROM.image");
    assert_eq!(images.values.len(), 3);
    let unpinned = lookup(attrs, "FROM.unpinned");
    assert!(unpinned
        .values
        .iter()
        .all(|value| *value == &Value::Bool(false)));
    assert_eq!(lookup(attrs, "USER").values[0].as_str(), Some("1000"));
    assert_eq!(lookup(attrs, "COPY").values.len(), 1);
    assert!(lookup(attrs, "ADD").missing);
    assert!(lookup(attrs, "HEALTHCHECK").missing);
    assert_eq!(lookup(attrs, "privileged").values[0], &Value::Bool(true));
    let run_priv = lookup(attrs, "RUN.privileged");
    assert!(run_priv.values.contains(&&Value::Bool(true)));
    let skipped = parse_file(
        Path::new("Dockerfile"),
        "# checkov:skip=CKV_DOCKER_1:base\nFROM nginx:1.25\n",
    );
    assert_eq!(skipped.resources[0].skips[0].check_id, "CKV_DOCKER_1");
    let empty = parse_file(Path::new("Dockerfile"), "\n# only comments\n");
    assert_eq!(empty.resources[0].resource_type, "dockerfile");
    assert!(lookup(&empty.resources[0].attributes, "FROM").missing);
    let cap = parse_file(
        Path::new("Dockerfile"),
        "FROM alpine:3.19\nRUN --cap-add=ALL echo hi\n",
    );
    assert_eq!(
        lookup(&cap.resources[0].attributes, "privileged").values[0],
        &Value::Bool(true)
    );
    let heredoc = parse_file(
        Path::new("Dockerfile"),
        "FROM alpine:3.19\nRUN <<EOF\necho hi\nEOF\nUSER app\n",
    );
    assert_eq!(
        lookup(&heredoc.resources[0].attributes, "USER").values[0].as_str(),
        Some("app")
    );
    assert_eq!(
        lookup(&heredoc.resources[0].attributes, "RUN").values.len(),
        1
    );
    let latest = parse_file(Path::new("Dockerfile"), "FROM nginx\n");
    assert_eq!(
        lookup(&latest.resources[0].attributes, "FROM.unpinned").values[0],
        &Value::Bool(true)
    );
}
