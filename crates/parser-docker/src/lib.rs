//! Parse Dockerfiles into a single resource of type `dockerfile`.

use std::collections::BTreeMap;
use std::path::Path;

use rustmaninoff_ir::{
    extract_skip_comments, skips_between, Framework, ParseOutput, Resource, ResourceKind, Value,
};

pub fn parse_file(path: &Path, source: &str) -> ParseOutput {
    let skips = extract_skip_comments(source);
    let instructions = parse_instructions(source);
    let attributes = attributes_from_instructions(&instructions);
    let end_line = source.lines().count().max(1);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Dockerfile")
        .to_string();
    ParseOutput {
        resources: vec![Resource {
            framework: Framework::Docker,
            kind: ResourceKind::Managed,
            resource_type: "dockerfile".into(),
            name,
            attributes,
            file: path.to_path_buf(),
            start_line: 1,
            end_line,
            skips: skips_between(&skips, 1, end_line),
        }],
        diagnostics: Vec::new(),
    }
}

#[derive(Debug)]
struct Instruction {
    name: String,
    args: String,
}

fn parse_instructions(source: &str) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut pending: Option<String> = None;
    let mut heredoc_end: Option<String> = None;
    for raw in source.lines() {
        if let Some(end) = heredoc_end.as_ref() {
            if let Some(current) = pending.as_mut() {
                current.push('\n');
                current.push_str(raw);
            }
            if raw.trim() == end {
                if let Some(line) = pending.take() {
                    if let Some(instruction) = split_instruction(&line) {
                        instructions.push(instruction);
                    }
                }
                heredoc_end = None;
            }
            continue;
        }
        let trimmed = raw.trim();
        if pending.is_none() && (trimmed.is_empty() || trimmed.starts_with('#')) {
            continue;
        }
        let logical = match pending.take() {
            Some(mut prefix) => {
                prefix.push(' ');
                prefix.push_str(trimmed.trim_start());
                prefix
            }
            None => trimmed.to_string(),
        };
        if logical.ends_with('\\') {
            pending = Some(logical.trim_end_matches('\\').trim_end().to_string());
            continue;
        }
        if let Some(delimiter) = heredoc_delimiter(&logical) {
            pending = Some(logical);
            heredoc_end = Some(delimiter);
            continue;
        }
        if let Some(instruction) = split_instruction(&logical) {
            instructions.push(instruction);
        }
    }
    if let Some(line) = pending {
        if let Some(instruction) = split_instruction(&line) {
            instructions.push(instruction);
        }
    }
    instructions
}

fn heredoc_delimiter(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let index = bytes.windows(2).position(|pair| pair == b"<<")?;
    let mut rest = line[index + 2..].trim_start();
    if rest.starts_with('-') {
        rest = rest[1..].trim_start();
    }
    rest = rest.trim_start_matches('"').trim_start_matches('\'');
    let token = rest
        .split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '\'')
        .next()
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

fn split_instruction(line: &str) -> Option<Instruction> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (name, rest) = match trimmed.split_once(char::is_whitespace) {
        Some((name, rest)) => (name, rest.trim()),
        None => (trimmed, ""),
    };
    Some(Instruction {
        name: name.to_ascii_uppercase(),
        args: rest.to_string(),
    })
}

fn attributes_from_instructions(instructions: &[Instruction]) -> Value {
    let mut from = Vec::new();
    let mut user = None;
    let mut add = Vec::new();
    let mut copy = Vec::new();
    let mut healthcheck = None;
    let mut run = Vec::new();
    let mut privileged = false;
    for instruction in instructions {
        match instruction.name.as_str() {
            "FROM" => from.push(from_object(&instruction.args)),
            "USER" => user = Some(maybe_string(first_token(&instruction.args))),
            "ADD" => add.push(arg_object(&instruction.args)),
            "COPY" => copy.push(arg_object(&instruction.args)),
            "HEALTHCHECK" if !instruction.args.trim().eq_ignore_ascii_case("NONE") => {
                healthcheck = Some(maybe_string(instruction.args.trim()));
            }
            "RUN" => {
                let is_privileged = run_is_privileged(&instruction.args);
                privileged |= is_privileged;
                let mut map = BTreeMap::new();
                map.insert("command".into(), maybe_string(&instruction.args));
                map.insert("privileged".into(), Value::Bool(is_privileged));
                run.push(Value::Object(map));
            }
            _ => {}
        }
    }
    let mut map = BTreeMap::new();
    if !from.is_empty() {
        map.insert("FROM".into(), Value::Array(from));
    }
    if let Some(user) = user {
        map.insert("USER".into(), user);
    }
    if !add.is_empty() {
        map.insert("ADD".into(), Value::Array(add));
    }
    if !copy.is_empty() {
        map.insert("COPY".into(), Value::Array(copy));
    }
    if let Some(healthcheck) = healthcheck {
        map.insert("HEALTHCHECK".into(), healthcheck);
    }
    if !run.is_empty() {
        map.insert("RUN".into(), Value::Array(run));
    }
    map.insert("privileged".into(), Value::Bool(privileged));
    Value::Object(map)
}

fn from_object(args: &str) -> Value {
    let image = from_image(args);
    let mut map = BTreeMap::new();
    map.insert("image".into(), maybe_string(&image));
    map.insert("unpinned".into(), from_unpinned(&image));
    Value::Object(map)
}

fn from_image(args: &str) -> String {
    let mut parts = args.split_whitespace();
    while let Some(part) = parts.next() {
        if part.starts_with("--") {
            if !part.contains('=') {
                parts.next();
            }
            continue;
        }
        return part.to_string();
    }
    String::new()
}

fn from_unpinned(image: &str) -> Value {
    let image = image.trim();
    if is_interpolation(image) {
        return Value::Unknown {
            expr: "interpolation".into(),
        };
    }
    if image.is_empty() {
        return Value::Bool(true);
    }
    if image.eq_ignore_ascii_case("scratch") {
        return Value::Bool(false);
    }
    if image.contains('@') {
        return Value::Bool(false);
    }
    let name = image.rsplit('/').next().unwrap_or(image);
    match name.rsplit_once(':') {
        Some((_, tag)) => Value::Bool(tag.is_empty() || tag.eq_ignore_ascii_case("latest")),
        None => Value::Bool(true),
    }
}

fn arg_object(args: &str) -> Value {
    let mut map = BTreeMap::new();
    map.insert("args".into(), maybe_string(args.trim()));
    Value::Object(map)
}

fn first_token(args: &str) -> &str {
    args.split_whitespace().next().unwrap_or(args).trim()
}

fn maybe_string(value: &str) -> Value {
    if is_interpolation(value) {
        Value::Unknown {
            expr: "interpolation".into(),
        }
    } else {
        Value::string(value)
    }
}

fn is_interpolation(value: &str) -> bool {
    if value.contains("${") {
        return true;
    }
    let bytes = value.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'$' {
            match bytes.get(index + 1) {
                Some(b'$') => index += 2,
                Some(next) if next.is_ascii_alphabetic() || *next == b'_' => return true,
                _ => index += 1,
            }
        } else {
            index += 1;
        }
    }
    false
}

fn run_is_privileged(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    lower.contains("--privileged")
        || lower.contains("chmod 777")
        || lower.contains("chmod -r 777")
        || lower.contains("chmod -r0777")
        || lower.contains("--cap-add=all")
        || lower.contains("--cap-add all")
        || lower.contains("--cap-add=sys_admin")
        || lower.contains("--cap-add sys_admin")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmaninoff_ir::lookup;

    #[test]
    fn parses_from_user_add_and_healthcheck() {
        let source = r#"
FROM nginx:latest
USER root
ADD src dest
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"#;
        let output = parse_file(Path::new("Dockerfile"), source);
        assert!(output.diagnostics.is_empty());
        assert_eq!(output.resources.len(), 1);
        let attrs = &output.resources[0].attributes;
        assert_eq!(
            lookup(attrs, "FROM.image").values[0].as_str(),
            Some("nginx:latest")
        );
        assert_eq!(lookup(attrs, "FROM.unpinned").values[0], &Value::Bool(true));
        assert_eq!(lookup(attrs, "USER").values[0].as_str(), Some("root"));
        assert_eq!(lookup(attrs, "ADD").values.len(), 1);
        assert!(lookup(attrs, "HEALTHCHECK").values[0].as_str().is_some());
    }

    #[test]
    fn interpolations_are_unknown() {
        let source = "FROM ${BASE}\nUSER ${APP_USER}\n";
        let output = parse_file(Path::new("Dockerfile"), source);
        let attrs = &output.resources[0].attributes;
        assert!(lookup(attrs, "FROM.image").unknown);
        assert!(lookup(attrs, "FROM.unpinned").unknown);
        assert!(lookup(attrs, "USER").unknown);
    }
}

#[cfg(test)]
mod coverage;
