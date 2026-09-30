use std::path::Path;

use rustmaninoff_ir::lookup;

use super::*;

#[test]
fn documents_lists_and_pod_specs() {
    let source = r#"
---
- kind: Pod
  apiVersion: v1
  metadata:
    annotations:
      checkov.io/skip: CKV_K8S_16=ok
  spec:
    containers:
      - name: a
        image: nginx:1.2
    initContainers:
      - name: b
        image: busybox:1.36
---
kind: ""
apiVersion: v1
---
: [
---
kind: CronJob
apiVersion: batch/v1
metadata:
  name: nightly
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: alpine:3
---
kind: ConfigMap
apiVersion: v1
data:
  a: b
---

---
kind: List
apiVersion: v1
---
42
"#;
    let output = parse_file(Path::new("pods.yaml"), source);
    assert!(!output.diagnostics.is_empty());
    let pod = output
        .resources
        .iter()
        .find(|item| item.resource_type == "Pod")
        .unwrap();
    assert_eq!(pod.name, "unnamed");
    assert!(!pod.skips.is_empty());
    match lookup(&pod.attributes, "_containers").values[0] {
        rustmaninoff_ir::Value::Array(items) => assert_eq!(items.len(), 2),
        other => panic!("{other:?}"),
    }
    assert!(output
        .resources
        .iter()
        .any(|item| item.resource_type == "CronJob"
            && lookup(&item.attributes, "_pod_spec").values.len() == 1));
    assert!(output
        .resources
        .iter()
        .any(|item| item.resource_type == "ConfigMap"));
}
