use std::path::Path;

use rustmaninoff_ir::lookup;

use super::*;

#[test]
fn json_templates_and_skipped_shapes() {
    let json = r#"{
      "Resources": {
        "Bucket": {
          "Type": "AWS::S3::Bucket",
          "Properties": {"BucketName": {"Ref": "Name"}, "Tags": [{"Key": {"Fn::Sub": "x"}}]}
        },
        "Text": "nope",
        "NoType": {"Properties": {}},
        "NoProps": {"Type": "AWS::S3::Bucket"}
      }
    }"#;
    let output = parse_file(Path::new("cfn.json"), json);
    assert_eq!(output.resources.len(), 2);
    assert!(lookup(&output.resources[0].attributes, "BucketName").unknown);
    assert_eq!(output.resources[0].start_line, 1);
    let bad_yaml = parse_file(Path::new("bad.yaml"), ":\n");
    assert!(!bad_yaml.diagnostics.is_empty());
    let bad = parse_file(Path::new("bad.json"), "{");
    assert!(!bad.diagnostics.is_empty());
    assert!(parse_file(Path::new("none.yaml"), "Description: only\n")
        .resources
        .is_empty());
    let missing_id = parse_file(
        Path::new("cfn.yaml"),
        "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n",
    );
    assert_eq!(missing_id.resources[0].start_line, 2);
}
