use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;

use super::{execute, request_from_args, Cli, Command};

fn dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rustmaninoff-cov-{label}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn run(args: &[&str]) -> anyhow::Result<i32> {
    let cli = Cli::try_parse_from(args).expect("args");
    execute(cli)
}

#[test]
fn scan_paths_frameworks_and_outputs() {
    let root = dir("scan");
    fs::write(
        root.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    fs::write(
        root.join("main.tf.json"),
        r#"{"resource":{"aws_ebs_volume":{"json":{"encrypted":false}}}}"#,
    )
    .unwrap();
    fs::write(root.join("note.txt"), "ignore").unwrap();
    fs::write(
        root.join("pod.yaml"),
        "kind: Pod\napiVersion: v1\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: nginx:latest\n      securityContext:\n        privileged: true\n",
    )
    .unwrap();
    fs::write(
        root.join("stack.yaml"),
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: logs\n",
    )
    .unwrap();
    let skipped = root.join("target");
    fs::create_dir(&skipped).unwrap();
    fs::write(
        skipped.join("hidden.tf"),
        "resource \"aws_ebs_volume\" \"x\" { encrypted = false }\n",
    )
    .unwrap();
    let json_file = root.join("out.json");
    let sarif_file = root.join("out.sarif");
    let junit_file = root.join("out.xml");
    let code = run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--output",
        "cli,json,sarif,junit",
        "--json-file",
        json_file.to_str().unwrap(),
        "--sarif-file",
        sarif_file.to_str().unwrap(),
        "--junit-file",
        junit_file.to_str().unwrap(),
        "--show-unknown",
        "--compact",
        "--show-passed",
        "--fail-on",
        "LOW",
    ])
    .unwrap();
    assert_eq!(code, 1);
    assert!(json_file.is_file());
    assert!(sarif_file.is_file());
    assert!(junit_file.is_file());
    let only = run(&[
        "rustmaninoff",
        "scan",
        root.join("main.tf").to_str().unwrap(),
        "--framework",
        "terraform",
        "--check",
        "CKV_AWS_3",
        "--output",
        "json",
    ])
    .unwrap();
    assert_eq!(only, 1);
    let clean = dir("clean");
    fs::write(
        clean.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" {\n  encrypted = true\n}\n",
    )
    .unwrap();
    assert_eq!(
        run(&["rustmaninoff", "scan", clean.to_str().unwrap()]).unwrap(),
        0
    );
    assert_eq!(
        run(&[
            "rustmaninoff",
            "scan",
            root.join("main.tf").to_str().unwrap(),
            "--soft-fail"
        ])
        .unwrap(),
        0
    );
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--framework",
        "nope"
    ])
    .is_err());
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--fail-on",
        "nope"
    ])
    .is_err());
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--output",
        "html"
    ])
    .is_err());
    let k8s_only = run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--framework",
        "kubernetes",
        "--output",
        "text",
    ])
    .unwrap();
    assert_eq!(k8s_only, 1);
    let missing = run(&[
        "rustmaninoff",
        "scan",
        root.join("missing").to_str().unwrap(),
    ])
    .unwrap();
    assert_eq!(missing, 0);
    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(clean);
}

#[test]
fn config_filters_and_external_checks() {
    let root = dir("config");
    fs::write(
        root.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    fs::write(
        root.join(".rustmaninoff.yaml"),
        "frameworks: [terraform]\nskip_checks: [CKV_AWS_999]\nfail_on: HIGH\nexcluded_paths: [vendor]\nshow_unknown: true\ncompact: true\n",
    )
    .unwrap();
    fs::create_dir(root.join("vendor")).unwrap();
    fs::write(
        root.join("vendor/skip.tf"),
        "resource \"aws_ebs_volume\" \"x\" { encrypted = false }\n",
    )
    .unwrap();
    let external = root.join("external");
    fs::create_dir(&external).unwrap();
    fs::write(
        external.join("extra.yaml"),
        "metadata:\n  id: EXT_1\n  name: extra\n  severity: LOW\nresource_types: [aws_ebs_volume]\ndefinition:\n  cond_type: attribute\n  attribute: encrypted\n  operator: equals\n  value: true\n",
    )
    .unwrap();
    let code = run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--skip-check",
        "CKV_AWS_3",
        "--external-checks-dir",
        external.to_str().unwrap(),
        "--fail-on",
        "LOW",
    ])
    .unwrap();
    assert_eq!(code, 1);
    let bad = root.join("bad.yaml");
    fs::write(&bad, "[\n").unwrap();
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--config",
        bad.to_str().unwrap()
    ])
    .is_err());
    let deep = root.join("deep.yaml");
    fs::write(&deep, "{".repeat(200)).unwrap();
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--config",
        deep.to_str().unwrap()
    ])
    .is_err());
    let huge = root.join("huge.yaml");
    let mut file = fs::File::create(&huge).unwrap();
    file.write_all(b"frameworks: []\n").unwrap();
    file.set_len(1_000_001).unwrap();
    drop(file);
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--config",
        huge.to_str().unwrap()
    ])
    .is_err());
    #[cfg(unix)]
    {
        let link = root.join("link.yaml");
        std::os::unix::fs::symlink(&bad, &link).unwrap();
        assert!(run(&[
            "rustmaninoff",
            "scan",
            root.to_str().unwrap(),
            "--config",
            link.to_str().unwrap()
        ])
        .is_err());
    }
    let cli = Cli::try_parse_from(["rustmaninoff", "scan"]).unwrap();
    let Command::Scan(args) = cli.command;
    let request = request_from_args(args).unwrap();
    assert!(!request.frameworks.is_empty());
    let blocked = root.join("blocked");
    fs::create_dir(&blocked).unwrap();
    let err = run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--external-checks-dir",
        blocked.join("missing").to_str().unwrap(),
        "--check",
        "CKV_AWS_3",
    ]);
    assert!(err.is_err());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn write_failure_is_reported() {
    let root = dir("write");
    fs::write(
        root.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" { encrypted = true }\n",
    )
    .unwrap();
    let err = run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--output",
        "json",
        "--json-file",
        root.to_str().unwrap(),
    ]);
    assert!(err.is_err());
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--output",
        "junit",
        "--junit-file",
        root.to_str().unwrap(),
    ])
    .is_err());
    assert!(run(&[
        "rustmaninoff",
        "scan",
        root.to_str().unwrap(),
        "--output",
        "sarif",
        "--sarif-file",
        root.to_str().unwrap(),
    ])
    .is_err());
    #[cfg(unix)]
    {
        let link = root.join("link.tf");
        std::os::unix::fs::symlink(root.join("main.tf"), &link).unwrap();
        assert_eq!(
            run(&["rustmaninoff", "scan", link.to_str().unwrap()]).unwrap(),
            0
        );
        assert!(
            super::classify_and_parse(&link, &[rustmaninoff_ir::Framework::Terraform]).is_none()
        );
    }
    let _ = fs::remove_dir_all(root);
}
