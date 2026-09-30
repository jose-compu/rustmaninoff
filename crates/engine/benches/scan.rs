use criterion::{black_box, Criterion};
use rustmaninoff_engine::{evaluate, parse_policy, Policy};
use rustmaninoff_ir::{Framework, Resource, Value};
use std::path::PathBuf;

fn policy() -> Policy {
    parse_policy(
        r#"
metadata:
  id: CKV_AWS_3
  name: encrypted
  severity: HIGH
  framework: terraform
resource_types: [aws_ebs_volume]
definition:
  cond_type: attribute
  attribute: encrypted
  operator: equals
  value: true
"#,
    )
    .unwrap()
}

fn resources(count: usize) -> Vec<Resource> {
    (0..count)
        .map(|index| Resource {
            framework: Framework::Terraform,
            resource_type: "aws_ebs_volume".into(),
            name: format!("v{index}"),
            attributes: Value::from_json(serde_json::json!({"encrypted": false, "size": 8})),
            file: PathBuf::from("bench.tf"),
            start_line: 1,
            end_line: 4,
            skips: Vec::new(),
        })
        .collect()
}

fn bench_eval(c: &mut Criterion) {
    let policies = vec![policy()];
    let resources = resources(2_000);
    c.bench_function("evaluate_2000_ebs", |b| {
        b.iter(|| {
            let findings = evaluate(black_box(&resources), black_box(&policies));
            black_box(findings.len())
        })
    });
}

criterion::criterion_group!(benches, bench_eval);
criterion::criterion_main!(benches);
