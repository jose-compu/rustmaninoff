use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rustmaninoff-bin-{label}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rustmaninoff"))
}

#[test]
fn binary_exits_clean_failed_and_usage() {
    let clean = dir("clean");
    fs::write(
        clean.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" {\n  encrypted = true\n}\n",
    )
    .unwrap();
    let ok = binary().arg("scan").arg(&clean).output().expect("run");
    assert_eq!(
        ok.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let bad = dir("bad");
    fs::write(
        bad.join("main.tf"),
        "resource \"aws_ebs_volume\" \"disk\" {\n  encrypted = false\n}\n",
    )
    .unwrap();
    let failed = binary().arg("scan").arg(&bad).output().expect("run");
    assert_eq!(failed.status.code(), Some(1));
    let usage = binary()
        .arg("scan")
        .arg(&bad)
        .arg("--framework")
        .arg("nope")
        .output()
        .expect("run");
    assert_eq!(usage.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&usage.stderr).contains("error:"));
    let _ = fs::remove_dir_all(clean);
    let _ = fs::remove_dir_all(bad);
}
