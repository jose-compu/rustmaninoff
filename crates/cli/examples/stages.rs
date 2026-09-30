//! Time each scan stage on a synthetic corpus. Release only.
//!
//! cargo run --release -p rustmaninoff --example stages

use std::path::Path;
use std::time::Instant;

use rayon::prelude::*;

use rustmaninoff::builtin_policies;
use rustmaninoff_engine::evaluate;
use rustmaninoff_ir::{Framework, Resource, Value};
use rustmaninoff_parser_cfn::parse_file as parse_cfn;
use rustmaninoff_parser_k8s::parse_file as parse_k8s;
use rustmaninoff_parser_terraform::parse_file as parse_tf;

fn main() {
    let tf_files = (0..40).map(terraform_file).collect::<Vec<_>>();
    let cfn_files = (0..20).map(cfn_file).collect::<Vec<_>>();
    let k8s_files = (0..20).map(k8s_file).collect::<Vec<_>>();
    println!(
        "corpus: {} terraform files, {} cloudformation, {} kubernetes",
        tf_files.len(),
        cfn_files.len(),
        k8s_files.len()
    );

    let tf = time("parse terraform", || {
        let mut resources = 0usize;
        for (index, source) in tf_files.iter().enumerate() {
            let output = parse_tf(Path::new(&format!("f{index}.tf")), source);
            assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
            resources += output.resources.len();
        }
        resources
    });
    println!("  terraform resources parsed: {tf}");
    let tf_parallel = time("parse terraform parallel", || {
        tf_files
            .par_iter()
            .enumerate()
            .map(|(index, source)| {
                let output = parse_tf(Path::new(&format!("f{index}.tf")), source);
                assert!(output.diagnostics.is_empty());
                output.resources.len()
            })
            .sum::<usize>()
    });
    println!("  terraform resources parsed in parallel: {tf_parallel}");

    let cfn = time("parse cloudformation", || {
        let mut resources = 0usize;
        for (index, source) in cfn_files.iter().enumerate() {
            let output = parse_cfn(Path::new(&format!("f{index}.yaml")), source);
            assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
            resources += output.resources.len();
        }
        resources
    });
    println!("  cloudformation resources parsed: {cfn}");

    let k8s = time("parse kubernetes", || {
        let mut resources = 0usize;
        for (index, source) in k8s_files.iter().enumerate() {
            let output = parse_k8s(Path::new(&format!("f{index}.yaml")), source);
            assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
            resources += output.resources.len();
        }
        resources
    });
    println!("  kubernetes resources parsed: {k8s}");

    let fat = terraform_file_resources(400);
    let fat_resources = time("parse one 400-resource terraform file", || {
        let output = parse_tf(Path::new("fat.tf"), &fat);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        output.resources.len()
    });
    println!("  fat file resources: {fat_resources}");

    let policies = time("load builtin policies cold", || {
        builtin_policies().expect("policies").len()
    });
    println!("  policies: {policies}");
    let warm = time("load builtin policies warm", || {
        builtin_policies().expect("policies").len()
    });
    println!("  policies warm: {warm}");
    let policies = builtin_policies().expect("policies");

    let mut resources = Vec::new();
    for (index, source) in tf_files.iter().enumerate() {
        resources.extend(parse_tf(Path::new(&format!("f{index}.tf")), source).resources);
    }
    for (index, source) in cfn_files.iter().enumerate() {
        resources.extend(parse_cfn(Path::new(&format!("f{index}.yaml")), source).resources);
    }
    for (index, source) in k8s_files.iter().enumerate() {
        resources.extend(parse_k8s(Path::new(&format!("f{index}.yaml")), source).resources);
    }
    println!("evaluation corpus: {} resources", resources.len());

    let findings = time("evaluate full builtin pack", || {
        evaluate(&resources, &policies).len()
    });
    println!("  findings: {findings}");

    let ebs = ebs_resources(2_000);
    let one = policies
        .iter()
        .find(|policy| {
            policy.id.as_ref() == "CKV_AWS_3" && policy.framework == Some(Framework::Terraform)
        })
        .cloned()
        .expect("CKV_AWS_3");
    let one_findings = time("evaluate CKV_AWS_3 on 2000 volumes", || {
        evaluate(&ebs, std::slice::from_ref(&one)).len()
    });
    println!("  findings: {one_findings}");

    let root = ebs[0].attributes.clone();
    time("lookup encrypted x 200000", || {
        for _ in 0..200_000 {
            let resolved = rustmaninoff_ir::lookup(&root, "encrypted");
            std::hint::black_box(resolved.values.len());
        }
        200_000
    });
}

fn time<T>(label: &str, body: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = body();
    let elapsed = start.elapsed();
    println!("{label}: {elapsed:.3?}");
    value
}

fn terraform_file(index: usize) -> String {
    terraform_file_resources(25 + (index % 5))
}

fn terraform_file_resources(count: usize) -> String {
    let mut out = String::new();
    for index in 0..count {
        match index % 4 {
            0 => out.push_str(&format!(
                "resource \"aws_ebs_volume\" \"v{index}\" {{\n  encrypted = false\n  size = 8\n}}\n"
            )),
            1 => out.push_str(&format!(
                "resource \"aws_security_group\" \"sg{index}\" {{\n  ingress {{\n    from_port = 22\n    to_port = 22\n    protocol = \"tcp\"\n    cidr_blocks = [\"0.0.0.0/0\"]\n  }}\n}}\n"
            )),
            2 => out.push_str(&format!(
                "resource \"aws_s3_bucket\" \"b{index}\" {{\n  bucket = \"logs-{index}\"\n}}\n"
            )),
            _ => out.push_str(&format!(
                "resource \"aws_iam_policy\" \"p{index}\" {{\n  policy = jsonencode({{\n    Statement = [{{\n      Effect = \"Allow\"\n      Action = \"s3:*\"\n      Resource = \"*\"\n    }}]\n  }})\n}}\n"
            )),
        }
    }
    out
}

fn cfn_file(index: usize) -> String {
    let mut out = String::from("AWSTemplateFormatVersion: \"2010-09-09\"\nResources:\n");
    for item in 0..15 {
        out.push_str(&format!(
            "  Bucket{index}{item}:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: logs-{index}-{item}\n"
        ));
    }
    out
}

fn k8s_file(index: usize) -> String {
    let mut out = String::new();
    for item in 0..8 {
        if item > 0 {
            out.push_str("---\n");
        }
        out.push_str(&format!(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app-{index}-{item}\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: nginx:latest\n          securityContext:\n            privileged: true\n"
        ));
    }
    out
}

fn ebs_resources(count: usize) -> Vec<Resource> {
    (0..count)
        .map(|index| Resource {
            framework: Framework::Terraform,
            resource_type: "aws_ebs_volume".into(),
            name: format!("v{index}"),
            attributes: Value::from_json(serde_json::json!({"encrypted": false, "size": 8})),
            file: Path::new("bench.tf").to_path_buf(),
            start_line: 1,
            end_line: 4,
            skips: Vec::new(),
        })
        .collect()
}
