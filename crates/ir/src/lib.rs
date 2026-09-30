//! Normalized infrastructure resources and attribute lookup.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// IaC language a resource was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    Terraform,
    CloudFormation,
    Kubernetes,
}

impl Framework {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "terraform" | "tf" => Some(Self::Terraform),
            "cloudformation" | "cfn" => Some(Self::CloudFormation),
            "kubernetes" | "k8s" => Some(Self::Kubernetes),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terraform => "terraform",
            Self::CloudFormation => "cloudformation",
            Self::Kubernetes => "kubernetes",
        }
    }
}

impl std::fmt::Display for Framework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Attribute value. Unknown marks interpolations and intrinsic functions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
    Unknown { expr: String },
}

impl Value {
    pub fn string(value: impl Into<String>) -> Self {
        let value = value.into();
        maybe_structured_string(value)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn pointer(&self, path: &str) -> Option<&Value> {
        let resolved = lookup(self, path);
        if resolved.unknown || resolved.missing {
            return None;
        }
        resolved.values.first().copied()
    }

    pub fn from_json(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(v) => Self::Bool(v),
            serde_json::Value::Number(v) => Self::Number(v),
            serde_json::Value::String(v) => Self::string(v),
            serde_json::Value::Array(items) => {
                Self::Array(items.into_iter().map(Self::from_json).collect())
            }
            serde_json::Value::Object(map) => Self::Object(
                map.into_iter()
                    .map(|(key, value)| (key, Self::from_json(value)))
                    .collect(),
            ),
        }
    }

    pub fn from_yaml(value: serde_yaml::Value) -> Self {
        match value {
            serde_yaml::Value::Null => Self::Null,
            serde_yaml::Value::Bool(v) => Self::Bool(v),
            serde_yaml::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Number(i.into())
                } else if let Some(u) = n.as_u64() {
                    Self::Number(u.into())
                } else if let Some(f) = n.as_f64() {
                    serde_json::Number::from_f64(f)
                        .map(Self::Number)
                        .unwrap_or(Self::Null)
                } else {
                    Self::String(n.to_string())
                }
            }
            serde_yaml::Value::String(v) => Self::string(v),
            serde_yaml::Value::Sequence(items) => {
                Self::Array(items.into_iter().map(Self::from_yaml).collect())
            }
            serde_yaml::Value::Mapping(map) => {
                let mut object = BTreeMap::new();
                for (key, value) in map {
                    let key = match key {
                        serde_yaml::Value::String(text) => text,
                        serde_yaml::Value::Bool(value) => value.to_string(),
                        serde_yaml::Value::Number(number) => number.to_string(),
                        serde_yaml::Value::Null => "null".to_string(),
                        other => serde_yaml::to_string(&other)
                            .unwrap_or_else(|_| "key".to_string())
                            .trim()
                            .to_string(),
                    };
                    object.insert(key, Self::from_yaml(value));
                }
                Self::Object(object)
            }
            serde_yaml::Value::Tagged(tagged) => Self::Unknown {
                expr: tagged.tag.to_string(),
            },
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Number(n) => n.as_f64(),
            Self::String(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

fn maybe_structured_string(value: String) -> Value {
    let trimmed = value.trim();
    let structured = (trimmed.starts_with('{') && trimmed.ends_with('}'))
        || (trimmed.starts_with('[') && trimmed.ends_with(']'));
    if structured {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
            return Value::from_json(parsed);
        }
    }
    Value::String(value)
}

/// Result of walking an attribute path across nested blocks and lists.
#[derive(Debug)]
pub struct Resolved<'a> {
    pub values: Vec<&'a Value>,
    pub missing: bool,
    pub unknown: bool,
}

impl<'a> Resolved<'a> {
    fn missing() -> Self {
        Self {
            values: Vec::new(),
            missing: true,
            unknown: false,
        }
    }

    fn unknown() -> Self {
        Self {
            values: Vec::new(),
            missing: false,
            unknown: true,
        }
    }

    fn one(value: &'a Value) -> Self {
        Self {
            values: vec![value],
            missing: false,
            unknown: false,
        }
    }

    fn merge(&mut self, other: Resolved<'a>) {
        self.values.extend(other.values);
        self.missing |= other.missing;
        self.unknown |= other.unknown;
    }
}

#[derive(Clone, Debug)]
enum Seg {
    Key(String),
    Index(usize),
}

/// Resolve `path` against `root`.
///
/// Dots and slashes separate keys. `[0]` is an index. Arrays of objects fan out
/// when the next segment is a key, so `ingress.cidr_blocks` visits every rule.
/// Attribute path parsed once and reused across resources.
#[derive(Clone, Debug)]
pub struct AttrPath {
    segs: Vec<Seg>,
}

impl AttrPath {
    pub fn parse(path: &str) -> Self {
        Self {
            segs: parse_path(path),
        }
    }
}

pub fn lookup<'a>(root: &'a Value, path: &str) -> Resolved<'a> {
    if path.is_empty() || path == "." {
        return root_value(root);
    }
    if !path
        .bytes()
        .any(|byte| byte == b'.' || byte == b'/' || byte == b'[')
    {
        return lookup_key(root, path);
    }
    lookup_path(root, &AttrPath::parse(path))
}

pub fn lookup_path<'a>(root: &'a Value, path: &AttrPath) -> Resolved<'a> {
    if path.segs.is_empty() {
        return root_value(root);
    }
    walk(root, &path.segs)
}

fn root_value(root: &Value) -> Resolved<'_> {
    if matches!(root, Value::Unknown { .. }) {
        Resolved::unknown()
    } else {
        Resolved::one(root)
    }
}

fn lookup_key<'a>(current: &'a Value, key: &str) -> Resolved<'a> {
    match current {
        Value::Unknown { .. } => Resolved::unknown(),
        Value::Object(map) => match map.get(key) {
            Some(Value::Unknown { .. }) => Resolved::unknown(),
            Some(value) => Resolved::one(value),
            None => Resolved::missing(),
        },
        Value::Array(items) => {
            if items.is_empty() {
                return Resolved::missing();
            }
            let mut acc = Resolved {
                values: Vec::new(),
                missing: false,
                unknown: false,
            };
            for item in items {
                acc.merge(lookup_key(item, key));
            }
            acc
        }
        _ => Resolved::missing(),
    }
}

fn parse_path(path: &str) -> Vec<Seg> {
    let mut segs = Vec::new();
    for part in path.replace('/', ".").split('.') {
        if part.is_empty() {
            continue;
        }
        if let Some(bracket) = part.find('[') {
            let name = &part[..bracket];
            if !name.is_empty() {
                segs.push(Seg::Key(name.to_string()));
            }
            let mut rest = &part[bracket..];
            while rest.starts_with('[') {
                let Some(end) = rest.find(']') else {
                    break;
                };
                if let Ok(index) = rest[1..end].parse::<usize>() {
                    segs.push(Seg::Index(index));
                }
                rest = &rest[end + 1..];
            }
            if !rest.is_empty() {
                segs.push(Seg::Key(rest.to_string()));
            }
        } else if part.chars().all(|ch| ch.is_ascii_digit()) {
            if let Ok(index) = part.parse::<usize>() {
                segs.push(Seg::Index(index));
            }
        } else {
            segs.push(Seg::Key(part.to_string()));
        }
    }
    segs
}

fn walk<'a>(current: &'a Value, segs: &[Seg]) -> Resolved<'a> {
    if matches!(current, Value::Unknown { .. }) {
        return Resolved::unknown();
    }
    if segs.is_empty() {
        return Resolved::one(current);
    }
    match current {
        Value::Object(map) => match &segs[0] {
            Seg::Key(key) => match map.get(key) {
                Some(value) => walk(value, &segs[1..]),
                None => Resolved::missing(),
            },
            Seg::Index(_) => Resolved::missing(),
        },
        Value::Array(items) => match &segs[0] {
            Seg::Index(index) => match items.get(*index) {
                Some(value) => walk(value, &segs[1..]),
                None => Resolved::missing(),
            },
            Seg::Key(_) => {
                if items.is_empty() {
                    return Resolved::missing();
                }
                let mut acc = Resolved {
                    values: Vec::new(),
                    missing: false,
                    unknown: false,
                };
                for item in items {
                    acc.merge(walk(item, segs));
                }
                acc
            }
        },
        _ => Resolved::missing(),
    }
}

/// Maximum bytes read from one IaC file.
pub const MAX_SOURCE_BYTES: u64 = 10_000_000;

/// Maximum bytes read from one policy or config file.
pub const MAX_POLICY_BYTES: u64 = 1_000_000;

/// Reject inputs that can blow the stack or expand YAML aliases without bound.
///
/// One linear pass. Normal Terraform, CloudFormation, and Kubernetes stay under the limits.
pub fn input_limit(source: &str) -> Option<&'static str> {
    const MAX_DEPTH: usize = 128;
    const MAX_ALIASES: usize = 256;
    const MAX_INDENT: usize = 512;
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut aliases = 0usize;
    let mut indent = 0usize;
    let mut line_start = true;
    let mut double_quote = false;
    let mut single_quote = false;
    let mut escape = false;
    let mut comment = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if comment {
            if byte == b'\n' {
                comment = false;
                line_start = true;
                indent = 0;
            }
            index += 1;
            continue;
        }
        if double_quote {
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                double_quote = false;
            }
            index += 1;
            continue;
        }
        if single_quote {
            if byte == b'\'' && bytes.get(index + 1) == Some(&b'\'') {
                index += 2;
                continue;
            }
            if byte == b'\'' {
                single_quote = false;
            }
            index += 1;
            continue;
        }
        if line_start {
            if byte == b' ' || byte == b'\t' {
                indent += 1;
                if indent > MAX_INDENT {
                    return Some("file indentation exceeds the safety limit");
                }
                index += 1;
                continue;
            }
            line_start = false;
        }
        match byte {
            b'\n' => {
                line_start = true;
                indent = 0;
            }
            b'#' => comment = true,
            b'/' if bytes.get(index + 1) == Some(&b'/') => comment = true,
            b'"' => double_quote = true,
            b'\'' => single_quote = true,
            b'{' | b'[' | b'(' => {
                depth += 1;
                if depth > MAX_DEPTH {
                    return Some("file nesting exceeds the safety limit");
                }
            }
            b'}' | b']' | b')' => depth = depth.saturating_sub(1),
            b'*' if is_yaml_alias(bytes, index) => {
                aliases += 1;
                if aliases > MAX_ALIASES {
                    return Some("YAML alias expansion exceeds the safety limit");
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn is_yaml_alias(bytes: &[u8], index: usize) -> bool {
    let Some(next) = bytes.get(index + 1) else {
        return false;
    };
    if !next.is_ascii_alphabetic() && *next != b'_' {
        return false;
    }
    match bytes.get(index.wrapping_sub(1)) {
        None => true,
        Some(prev) => !prev.is_ascii_alphanumeric() && *prev != b'_' && *prev != b'*',
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skip {
    pub check_id: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocatedSkip {
    pub line: usize,
    pub skip: Skip,
}

/// A parsed infrastructure object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub framework: Framework,
    pub resource_type: String,
    pub name: String,
    pub attributes: Value,
    pub file: PathBuf,
    pub start_line: usize,
    pub end_line: usize,
    pub skips: Vec<Skip>,
}

/// A file that was recognized but could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOutput {
    pub resources: Vec<Resource>,
    pub diagnostics: Vec<Diagnostic>,
}

/// `# checkov:skip=CKV_AWS_1:reason` and `//` comments.
fn skip_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r"(?m)^\s*(?:#|//)\s*checkov:skip=([A-Za-z0-9_]+)\s*(?::\s*(.*?))?\s*$")
            .expect("skip regex")
    })
}

pub fn extract_skip_comments(src: &str) -> Vec<LocatedSkip> {
    let pattern = skip_pattern();
    let mut found = Vec::new();
    for captures in pattern.captures_iter(src) {
        let matched = captures.get(0).expect("full match");
        let line = byte_to_line(src, matched.start());
        let reason = captures
            .get(2)
            .map(|item| item.as_str().trim().to_string())
            .filter(|item| !item.is_empty());
        found.push(LocatedSkip {
            line,
            skip: Skip {
                check_id: captures[1].to_string(),
                reason,
            },
        });
    }
    found
}

pub fn byte_to_line(src: &str, byte: usize) -> usize {
    src[..byte.min(src.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

pub fn skips_between(located: &[LocatedSkip], start_line: usize, end_line: usize) -> Vec<Skip> {
    let window_start = start_line.saturating_sub(8);
    let end_line = end_line.max(start_line);
    located
        .iter()
        .filter(|item| item.line >= window_start && item.line <= end_line)
        .map(|item| item.skip.clone())
        .collect()
}

/// Checkov-style annotation values: `CKV_K8S_16=reason`.
pub fn skips_from_annotations(metadata: &Value) -> Vec<Skip> {
    let Some(annotations) = metadata.get("annotations").and_then(|value| match value {
        Value::Object(map) => Some(map),
        _ => None,
    }) else {
        return Vec::new();
    };
    let mut skips = Vec::new();
    for (key, value) in annotations {
        if !key.starts_with("checkov.io/skip") {
            continue;
        }
        let Some(raw) = value.as_str() else {
            continue;
        };
        let (check_id, reason) = split_annotation(raw);
        if !check_id.is_empty() {
            skips.push(Skip { check_id, reason });
        }
    }
    skips
}

fn split_annotation(raw: &str) -> (String, Option<String>) {
    match raw.split_once('=') {
        Some((id, reason)) => {
            let reason = reason.trim();
            (
                id.trim().to_string(),
                if reason.is_empty() {
                    None
                } else {
                    Some(reason.to_string())
                },
            )
        }
        None => (raw.trim().to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(entries: Vec<(&str, Value)>) -> Value {
        Value::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    #[test]
    fn fans_out_nested_blocks() {
        let root = obj(vec![(
            "ingress",
            Value::Array(vec![
                obj(vec![(
                    "cidr_blocks",
                    Value::Array(vec![Value::string("0.0.0.0/0")]),
                )]),
                obj(vec![(
                    "cidr_blocks",
                    Value::Array(vec![Value::string("10.0.0.0/8")]),
                )]),
            ]),
        )]);
        let resolved = lookup(&root, "ingress.cidr_blocks");
        assert_eq!(resolved.values.len(), 2);
        assert!(!resolved.missing);
        assert!(!resolved.unknown);
    }

    #[test]
    fn unknown_short_circuits() {
        let root = obj(vec![(
            "encrypted",
            Value::Unknown {
                expr: "var.encrypted".into(),
            },
        )]);
        let resolved = lookup(&root, "encrypted");
        assert!(resolved.unknown);
    }

    #[test]
    fn parses_skip_comments() {
        let src = "# checkov:skip=CKV_AWS_3:dev volume\nresource \"aws_ebs_volume\" \"bad\" {\n}\n";
        let skips = extract_skip_comments(src);
        assert_eq!(skips.len(), 1);
        assert_eq!(skips[0].skip.check_id, "CKV_AWS_3");
        assert_eq!(skips[0].skip.reason.as_deref(), Some("dev volume"));
        assert_eq!(skips[0].line, 1);
    }

    #[test]
    fn typical_iac_passes_the_input_limit() {
        let source = r#"
# checkov:skip=CKV_AWS_3:reason
resource "aws_security_group" "sg" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
        assert!(input_limit(source).is_none());
        let quoted = "Action: '*'\nResource: \"*\"\n";
        assert!(input_limit(quoted).is_none());
    }

    #[test]
    fn deep_nesting_and_alias_bombs_are_rejected() {
        let mut deep = String::new();
        for _ in 0..200 {
            deep.push('{');
        }
        assert!(input_limit(&deep).is_some());
        let mut aliases = String::from("a: &a x\n");
        for index in 0..300 {
            aliases.push_str(&format!("k{index}: *a\n"));
        }
        assert!(input_limit(&aliases).is_some());
    }
}

#[cfg(test)]
mod coverage;
