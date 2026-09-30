use std::path::Path;

use rustmaninoff_ir::lookup;

use super::*;

#[test]
fn expressions_rules_and_json() {
    let source = r#"
# }
resource "aws_security_group" "sg" {
  name = "app"
  description = <<-EOT
    hello
  EOT
  tag = "hello ${var.name}"
  raw = null
  ratio = 1.5
  flag = true
  wrapped = (1)
  choice = true ? "yes" : "no"
  other = false ? "yes" : "no"
  maybe = var.x ? "yes" : "no"
  encoded = jsonencode({ name = "a" })
  missing = jsonencode()
  called = foo()
  note = "brace } \"x\""
  # }
  // }
  user_data = <<-EOT
resourceX
resource
resource "nope
resource "aws_ebs_volume" "open"
resource "a\"b" "n" {
  EOT
  big = 9223372036854775808
  protocol = true
  obj = { name = "a", (1) = "b" }
  ingress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    protocol = -1
    from_port = 1
    to_port = 2
  }
  dynamic "rule" {
    for_each = []
    content {}
  }
}
resource "aws_vpc_security_group_ingress_rule" "in" {
  from_port = 22
}
resource "aws_vpc_security_group_egress_rule" "out" {
  from_port = 80
}
resource "aws_ebs_volume" "a" {
  encrypted = false
}
resource "aws_ebs_volume" "a" {
  encrypted = true
}
data "aws_ami" "ubuntu" {
  most_recent = true
}
"#;
    let output = parse_file(Path::new("main.tf"), source);
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert!(output
        .resources
        .iter()
        .all(|item| item.resource_type != "aws_ami"));
    let sg = output
        .resources
        .iter()
        .find(|item| item.resource_type == "aws_security_group")
        .unwrap();
    assert!(lookup(&sg.attributes, "encoded").values[0]
        .get("name")
        .is_some());
    assert!(lookup(&sg.attributes, "tag").unknown);
    assert!(lookup(&sg.attributes, "maybe").unknown);
    assert!(lookup(&sg.attributes, "rule").unknown);
    let ingress = lookup(&sg.attributes, "ingress").values[0];
    assert_eq!(lookup(ingress, "to_port").values[0].as_f64(), Some(65535.0));
    let rule = output
        .resources
        .iter()
        .find(|item| item.resource_type == "aws_vpc_security_group_ingress_rule")
        .unwrap();
    assert_eq!(
        lookup(&rule.attributes, "type").values[0].as_str(),
        Some("ingress")
    );
    assert_eq!(
        output
            .resources
            .iter()
            .filter(|item| item.name == "a")
            .count(),
        2
    );
    let broken = parse_file(Path::new("bad.tf"), "resource \"aws_ebs_volume\" \"bad\" {");
    assert!(!broken.diagnostics.is_empty());
    let json = parse_file(
        Path::new("main.tf.json"),
        r#"{"resource":{"aws_ebs_volume":{"disk":{"encrypted":false,"note":"a ${var.x} %{if true}x%{endif}","tags":["a ${x}"]},"stringy":"hello ${var.x}"},"aws_s3_bucket":"nope"}}"#,
    );
    assert!(!json.resources.is_empty());
    assert!(json
        .resources
        .iter()
        .any(|item| lookup(&item.attributes, "note").unknown));
    let empty = parse_file(Path::new("empty.tf.json"), r#"{"locals":{}}"#);
    assert!(empty.resources.is_empty());
    let bad_json = parse_file(Path::new("bad.tf.json"), "{");
    assert!(!bad_json.diagnostics.is_empty());
    let trailing = "resource \"aws_ebs_volume\" \"z\" {\n  encrypted = true\n}\n# tail";
    let parsed = parse_file(Path::new("trail.tf"), trailing);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
}
