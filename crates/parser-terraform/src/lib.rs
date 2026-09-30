//! Parse Terraform `.tf` and `.tf.json` into resources.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use hcl::expr::{Expression, FuncCall, ObjectKey, TemplateExpr};
use hcl::structure::Body;
use rustmaninoff_ir::{
    extract_skip_comments, skips_between, Framework, ParseOutput, Resource, Value,
};

pub fn parse_file(path: &Path, source: &str) -> ParseOutput {
    if path.extension().and_then(|ext| ext.to_str()) == Some("json")
        || path.to_string_lossy().ends_with(".tf.json")
    {
        return parse_json(path, source);
    }
    match hcl::from_str::<Body>(source) {
        Ok(body) => parse_body(path, source, &body),
        Err(err) => ParseOutput {
            resources: Vec::new(),
            diagnostics: vec![rustmaninoff_ir::Diagnostic {
                file: path.to_path_buf(),
                line: 1,
                message: err.to_string(),
            }],
        },
    }
}

fn parse_body(path: &Path, source: &str, body: &Body) -> ParseOutput {
    let spans = index_block_spans(source);
    let skips = extract_skip_comments(source);
    let mut output = ParseOutput::default();
    let mut seen = HashMap::<(String, String), usize>::new();
    for block in body.blocks() {
        if block.identifier() != "resource" {
            continue;
        }
        let labels: Vec<String> = block
            .labels()
            .iter()
            .map(|label| label.as_str().to_string())
            .collect();
        if labels.len() < 2 {
            continue;
        }
        let occurrence = *seen
            .entry((labels[0].clone(), labels[1].clone()))
            .or_insert(0);
        seen.insert((labels[0].clone(), labels[1].clone()), occurrence + 1);
        let (start_line, end_line) = spans
            .get(labels[0].as_str())
            .and_then(|by_name| by_name.get(labels[1].as_str()))
            .and_then(|items| items.get(occurrence))
            .copied()
            .unwrap_or((1, 1));
        let mut attributes = body_to_value(block.body());
        normalize_tree(&mut attributes);
        if labels[0] == "aws_vpc_security_group_ingress_rule" {
            insert_type(&mut attributes, "ingress");
        } else if labels[0] == "aws_vpc_security_group_egress_rule" {
            insert_type(&mut attributes, "egress");
        }
        output.resources.push(Resource {
            framework: Framework::Terraform,
            resource_type: labels[0].clone(),
            name: labels[1].clone(),
            attributes,
            file: path.to_path_buf(),
            start_line,
            end_line,
            skips: skips_between(&skips, start_line, end_line),
        });
    }
    output
}

fn insert_type(attributes: &mut Value, type_name: &str) {
    if let Value::Object(map) = attributes {
        map.entry("type".to_string())
            .or_insert_with(|| Value::string(type_name));
    }
}

fn body_to_value(body: &Body) -> Value {
    let mut map = BTreeMap::new();
    for attribute in body.attributes() {
        map.insert(attribute.key().to_string(), expr_to_value(attribute.expr()));
    }
    let mut blocks: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for block in body.blocks() {
        if block.identifier() == "dynamic" {
            let name = block
                .labels()
                .iter()
                .next()
                .map(|label| label.as_str().to_string())
                .unwrap_or_else(|| "dynamic".to_string());
            map.insert(
                name,
                Value::Unknown {
                    expr: "dynamic".into(),
                },
            );
            continue;
        }
        blocks
            .entry(block.identifier().to_string())
            .or_default()
            .push(body_to_value(block.body()));
    }
    for (name, items) in blocks {
        map.insert(name, Value::Array(items));
    }
    Value::Object(map)
}

fn normalize_tree(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                normalize_tree(item);
            }
        }
        Value::Object(map) => {
            normalize_rule(map);
            for child in map.values_mut() {
                normalize_tree(child);
            }
        }
        _ => {}
    }
}

fn normalize_rule(map: &mut BTreeMap<String, Value>) {
    let all_protocols = map.get("protocol").map(|value| match value {
        Value::String(text) => text == "-1",
        Value::Number(number) => number.as_i64() == Some(-1),
        _ => false,
    });
    if all_protocols != Some(true) {
        return;
    }
    let from_zero = map
        .get("from_port")
        .and_then(Value::as_f64)
        .is_some_and(|port| port == 0.0);
    let to_zero = map
        .get("to_port")
        .and_then(Value::as_f64)
        .is_some_and(|port| port == 0.0);
    if from_zero && to_zero {
        map.insert("to_port".to_string(), Value::Number(65535.into()));
    }
}

fn expr_to_value(expr: &Expression) -> Value {
    match expr {
        Expression::Null => Value::Null,
        Expression::Bool(value) => Value::Bool(*value),
        Expression::Number(number) => number_value(number),
        Expression::String(value) => Value::string(value.clone()),
        Expression::Array(items) => Value::Array(items.iter().map(expr_to_value).collect()),
        Expression::Object(object) => {
            let mut map = BTreeMap::new();
            let mut unknown = false;
            for (key, value) in object.iter() {
                match object_key(key) {
                    Some(name) => {
                        map.insert(name, expr_to_value(value));
                    }
                    None => unknown = true,
                }
            }
            if unknown {
                Value::Unknown {
                    expr: "object".into(),
                }
            } else {
                Value::Object(map)
            }
        }
        Expression::TemplateExpr(template) => template_value(template),
        Expression::FuncCall(call) => func_value(call),
        Expression::Parenthesis(inner) => expr_to_value(inner),
        Expression::Conditional(conditional) => match expr_to_value(&conditional.cond_expr) {
            Value::Bool(true) => expr_to_value(&conditional.true_expr),
            Value::Bool(false) => expr_to_value(&conditional.false_expr),
            _ => Value::Unknown {
                expr: "conditional".into(),
            },
        },
        _ => Value::Unknown {
            expr: "expression".into(),
        },
    }
}

fn number_value(number: &hcl::Number) -> Value {
    let text = number.to_string();
    if let Ok(value) = text.parse::<i64>() {
        return Value::Number(value.into());
    }
    if let Ok(value) = text.parse::<u64>() {
        return Value::Number(value.into());
    }
    if let Ok(value) = text.parse::<f64>() {
        if let Some(number) = serde_json::Number::from_f64(value) {
            return Value::Number(number);
        }
    }
    Value::string(text)
}

fn object_key(key: &ObjectKey) -> Option<String> {
    match key {
        ObjectKey::Identifier(ident) => Some(ident.to_string()),
        ObjectKey::Expression(expr) => match expr_to_value(expr) {
            Value::String(value) => Some(value),
            _ => None,
        },
        _ => None,
    }
}

fn template_value(template: &TemplateExpr) -> Value {
    let raw = match template {
        TemplateExpr::QuotedString(value) => value.clone(),
        TemplateExpr::Heredoc(heredoc) => heredoc.template.clone(),
    };
    if raw.contains("${") || raw.contains("%{") {
        Value::Unknown {
            expr: "template".into(),
        }
    } else {
        Value::string(raw)
    }
}

fn func_value(call: &FuncCall) -> Value {
    let name = call.name.name.as_str();
    if name == "jsonencode" {
        if let Some(arg) = call.args.first() {
            return expr_to_value(arg);
        }
    }
    Value::Unknown {
        expr: name.to_string(),
    }
}

fn parse_json(path: &Path, source: &str) -> ParseOutput {
    let parsed: serde_json::Value = match serde_json::from_str(source) {
        Ok(value) => value,
        Err(err) => {
            return ParseOutput {
                diagnostics: vec![rustmaninoff_ir::Diagnostic {
                    file: path.to_path_buf(),
                    line: 1,
                    message: err.to_string(),
                }],
                resources: Vec::new(),
            };
        }
    };
    let skips = skips_between(&extract_skip_comments(source), 1, usize::MAX);
    let mut output = ParseOutput::default();
    let Some(resources) = parsed.get("resource").and_then(|value| value.as_object()) else {
        return output;
    };
    for (resource_type, named) in resources {
        let Some(named) = named.as_object() else {
            continue;
        };
        for (name, attributes) in named {
            let mut attributes = json_value(attributes);
            if let Value::String(text) = &attributes {
                if text.contains("${") {
                    attributes = Value::Unknown {
                        expr: "template".into(),
                    };
                }
            }
            mark_json_templates(&mut attributes);
            normalize_tree(&mut attributes);
            output.resources.push(Resource {
                framework: Framework::Terraform,
                resource_type: resource_type.clone(),
                name: name.clone(),
                attributes,
                file: path.to_path_buf(),
                start_line: 1,
                end_line: 1,
                skips: skips.clone(),
            });
        }
    }
    output
}

fn json_value(value: &serde_json::Value) -> Value {
    Value::from_json(value.clone())
}

fn mark_json_templates(value: &mut Value) {
    match value {
        Value::String(text) if text.contains("${") || text.contains("%{") => {
            *value = Value::Unknown {
                expr: "template".into(),
            };
        }
        Value::Array(items) => {
            for item in items {
                mark_json_templates(item);
            }
        }
        Value::Object(map) => {
            for child in map.values_mut() {
                mark_json_templates(child);
            }
        }
        _ => {}
    }
}

fn index_block_spans(source: &str) -> HashMap<String, HashMap<String, Vec<(usize, usize)>>> {
    let bytes = source.as_bytes();
    let mut spans: HashMap<String, HashMap<String, Vec<(usize, usize)>>> = HashMap::new();
    let mut index = 0usize;
    let mut line = 1usize;
    while index < bytes.len() {
        let mut cursor = index;
        while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
            cursor += 1;
        }
        if let Some(hit) = resource_header(bytes, cursor) {
            let end_byte = match_braces(source, hit.open).unwrap_or(hit.open.saturating_add(1));
            let next = end_byte.min(bytes.len());
            let end_line = line + count_newlines(&bytes[index..next]);
            spans
                .entry(hit.type_name)
                .or_default()
                .entry(hit.name)
                .or_default()
                .push((line, end_line.max(line)));
            line = end_line;
            index = next;
            continue;
        }
        if let Some(rel) = bytes[index..].iter().position(|byte| *byte == b'\n') {
            index += rel + 1;
            line += 1;
        } else {
            break;
        }
    }
    spans
}

struct ResourceHeader {
    type_name: String,
    name: String,
    open: usize,
}

fn resource_header(bytes: &[u8], mut cursor: usize) -> Option<ResourceHeader> {
    let keyword = b"resource";
    if bytes.get(cursor..cursor + keyword.len()) != Some(keyword.as_slice()) {
        return None;
    }
    cursor += keyword.len();
    if bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
    {
        return None;
    }
    cursor = skip_ws(bytes, cursor);
    let (type_name, cursor) = parse_quoted(bytes, cursor)?;
    let cursor = skip_ws(bytes, cursor);
    let (name, cursor) = parse_quoted(bytes, cursor)?;
    let cursor = skip_ws(bytes, cursor);
    if bytes.get(cursor) != Some(&b'{') {
        return None;
    }
    Some(ResourceHeader {
        type_name,
        name,
        open: cursor,
    })
}

fn skip_ws(bytes: &[u8], mut cursor: usize) -> usize {
    while cursor < bytes.len() && matches!(bytes[cursor], b' ' | b'\t') {
        cursor += 1;
    }
    cursor
}

fn parse_quoted(bytes: &[u8], cursor: usize) -> Option<(String, usize)> {
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    let mut index = cursor + 1;
    let start = index;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            b'"' => {
                let text = String::from_utf8_lossy(&bytes[start..index]).replace("\\\"", "\"");
                return Some((text, index + 1));
            }
            _ => index += 1,
        }
    }
    None
}

fn count_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

fn match_braces(source: &str, open: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut index = open;
    let mut line_comment = false;
    let mut string = false;
    let mut escape = false;
    while index < bytes.len() {
        let ch = bytes[index];
        if line_comment {
            if ch == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if string {
            if escape {
                escape = false;
            } else if ch == b'\\' {
                escape = true;
            } else if ch == b'"' {
                string = false;
            }
            index += 1;
            continue;
        }
        match ch {
            b'#' => line_comment = true,
            b'/' if bytes.get(index + 1) == Some(&b'/') => line_comment = true,
            b'"' => string = true,
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmaninoff_ir::lookup;

    #[test]
    fn parses_resource_attributes_and_blocks() {
        let source = r#"
resource "aws_security_group" "bad" {
  description = "open"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        let output = parse_file(Path::new("main.tf"), source);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        assert_eq!(output.resources.len(), 1);
        let resolved = lookup(&output.resources[0].attributes, "ingress.from_port");
        assert_eq!(resolved.values.len(), 1);
        assert_eq!(resolved.values[0].as_f64(), Some(22.0));
    }

    #[test]
    fn jsonencode_stays_structured() {
        let source = r#"
resource "aws_iam_policy" "bad" {
  name = "admin"
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
"#;
        let output = parse_file(Path::new("iam.tf"), source);
        assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
        let action = lookup(&output.resources[0].attributes, "policy.Statement.Action");
        assert_eq!(action.values.len(), 1);
        assert_eq!(action.values[0].as_str(), Some("*"));
    }

    #[test]
    fn interpolation_is_unknown() {
        let source = r#"
resource "aws_ebs_volume" "x" {
  availability_zone = "us-east-1a"
  size              = 8
  encrypted         = var.encrypted
}
"#;
        let output = parse_file(Path::new("vol.tf"), source);
        let resolved = lookup(&output.resources[0].attributes, "encrypted");
        assert!(resolved.unknown);
    }
}

#[cfg(test)]
mod coverage;
