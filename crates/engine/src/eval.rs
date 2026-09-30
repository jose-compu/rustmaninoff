//! Attribute condition evaluation.

use rustmaninoff_ir::{lookup_path, AttrPath, Value};

use crate::policy::{yaml_to_value, Severity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operator {
    Equals,
    NotEquals,
    EqualsAny,
    Exists,
    NotExists,
    Contains,
    NotContains,
    Within,
    NotWithin,
    RegexMatch,
    NotRegexMatch,
    StartingWith,
    NotStartingWith,
    EndingWith,
    NotEndingWith,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    IsEmpty,
    IsNotEmpty,
    IsTrue,
    IsFalse,
    LengthEquals,
    LengthGreaterThan,
    LengthGreaterThanOrEqual,
    LengthLessThan,
    LengthLessThanOrEqual,
    Intersects,
    NotIntersects,
    Any,
    ImageTagPinned,
}

impl Operator {
    pub fn parse(text: &str) -> Option<Self> {
        let normalized = text.trim().to_ascii_lowercase().replace([' ', '-'], "_");
        Some(match normalized.as_str() {
            "equals" | "eq" => Self::Equals,
            "not_equals" | "not_eq" => Self::NotEquals,
            "equals_any" | "any_equals" => Self::EqualsAny,
            "exists" => Self::Exists,
            "not_exists" | "notexists" => Self::NotExists,
            "contains" => Self::Contains,
            "not_contains" => Self::NotContains,
            "within" => Self::Within,
            "not_within" => Self::NotWithin,
            "regex_match" => Self::RegexMatch,
            "not_regex_match" => Self::NotRegexMatch,
            "starting_with" => Self::StartingWith,
            "not_starting_with" => Self::NotStartingWith,
            "ending_with" => Self::EndingWith,
            "not_ending_with" => Self::NotEndingWith,
            "greater_than" => Self::GreaterThan,
            "greater_than_or_equal" => Self::GreaterThanOrEqual,
            "less_than" => Self::LessThan,
            "less_than_or_equal" => Self::LessThanOrEqual,
            "is_empty" => Self::IsEmpty,
            "is_not_empty" => Self::IsNotEmpty,
            "is_true" => Self::IsTrue,
            "is_false" => Self::IsFalse,
            "length_equals" => Self::LengthEquals,
            "length_greater_than" => Self::LengthGreaterThan,
            "length_greater_than_or_equal" => Self::LengthGreaterThanOrEqual,
            "length_less_than" => Self::LengthLessThan,
            "length_less_than_or_equal" => Self::LengthLessThanOrEqual,
            "intersects" => Self::Intersects,
            "not_intersects" => Self::NotIntersects,
            "any" => Self::Any,
            "image_tag_pinned" => Self::ImageTagPinned,
            _ => return None,
        })
    }

    fn default_missing(self) -> Missing {
        match self {
            Self::NotEquals
            | Self::NotExists
            | Self::NotContains
            | Self::NotWithin
            | Self::NotRegexMatch
            | Self::NotStartingWith
            | Self::NotEndingWith
            | Self::NotIntersects
            | Self::IsEmpty => Missing::Pass,
            _ => Missing::Fail,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Cond {
    Attribute {
        path: AttrPath,
        operator: Operator,
        value: Option<Value>,
        missing: Option<Missing>,
        regex: Option<regex::Regex>,
    },
    And(Vec<Cond>),
    Or(Vec<Cond>),
    Not(Box<Cond>),
    NoElement {
        path: AttrPath,
        where_cond: Box<Cond>,
    },
    ForbidResource,
}

impl Cond {
    pub fn from_yaml(value: &serde_yaml::Value) -> Result<Self, String> {
        let map = value
            .as_mapping()
            .ok_or_else(|| "condition must be a mapping".to_string())?;
        if let Some(items) = mapping_get(map, "and") {
            return Ok(Self::And(parse_list(items)?));
        }
        if let Some(items) = mapping_get(map, "or") {
            return Ok(Self::Or(parse_list(items)?));
        }
        if let Some(item) = mapping_get(map, "not") {
            return Ok(Self::Not(Box::new(Self::from_yaml(item)?)));
        }
        let kind = mapping_get(map, "cond_type")
            .and_then(|item| item.as_str())
            .unwrap_or("attribute");
        match kind {
            "attribute" => {
                let attribute = required_string(map, "attribute")?;
                let operator = Operator::parse(&required_string(map, "operator")?)
                    .ok_or_else(|| format!("unknown operator on attribute {attribute}"))?;
                let value = mapping_get(map, "value").map(yaml_to_value);
                let missing = mapping_get(map, "missing")
                    .and_then(|item| item.as_str())
                    .map(parse_missing)
                    .transpose()?;
                let regex = if matches!(operator, Operator::RegexMatch | Operator::NotRegexMatch) {
                    value
                        .as_ref()
                        .and_then(Value::as_str)
                        .and_then(compile_pattern)
                } else {
                    None
                };
                Ok(Self::Attribute {
                    path: AttrPath::parse(&attribute),
                    operator,
                    value,
                    missing,
                    regex,
                })
            }
            "no_element" => {
                let attribute = required_string(map, "attribute")?;
                let where_value = mapping_get(map, "where")
                    .ok_or_else(|| format!("no_element {attribute} is missing where"))?;
                Ok(Self::NoElement {
                    path: AttrPath::parse(&attribute),
                    where_cond: Box::new(Self::from_yaml(where_value)?),
                })
            }
            "forbid_resource" => Ok(Self::ForbidResource),
            other => Err(format!("unsupported cond_type '{other}'")),
        }
    }
}

fn parse_missing(text: &str) -> Result<Missing, String> {
    match text.trim().to_ascii_lowercase().as_str() {
        "pass" => Ok(Missing::Pass),
        "fail" => Ok(Missing::Fail),
        "unknown" => Ok(Missing::Unknown),
        other => Err(format!("unknown missing behavior '{other}'")),
    }
}

fn parse_list(value: &serde_yaml::Value) -> Result<Vec<Cond>, String> {
    let items = value
        .as_sequence()
        .ok_or_else(|| "logical operator expects a list".to_string())?;
    items.iter().map(Cond::from_yaml).collect()
}

fn mapping_get<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
    map.iter()
        .find(|(candidate, _)| candidate.as_str() == Some(key))
        .map(|(_, value)| value)
}

fn compile_pattern(pattern: &str) -> Option<regex::Regex> {
    if pattern.len() > 1_024 {
        return None;
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .nest_limit(32)
        .build()
        .ok()
}

fn required_string(map: &serde_yaml::Mapping, key: &str) -> Result<String, String> {
    mapping_get(map, key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing string field '{key}'"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Status {
    Passed = 0,
    Skipped = 1,
    Unknown = 2,
    Failed = 3,
}

pub fn eval_cond(cond: &Cond, root: &Value) -> Status {
    match cond {
        Cond::Attribute {
            path,
            operator,
            value,
            missing,
            regex,
        } => eval_attribute(
            root,
            path,
            *operator,
            value.as_ref(),
            *missing,
            regex.as_ref(),
        ),
        Cond::And(items) => items.iter().map(|item| eval_cond(item, root)).fold(
            Status::Passed,
            |acc, status| match (acc, status) {
                (Status::Failed, _) | (_, Status::Failed) => Status::Failed,
                (Status::Unknown, _) | (_, Status::Unknown) => Status::Unknown,
                _ => Status::Passed,
            },
        ),
        Cond::Or(items) => items.iter().map(|item| eval_cond(item, root)).fold(
            Status::Failed,
            |acc, status| match (acc, status) {
                (Status::Passed, _) | (_, Status::Passed) => Status::Passed,
                (Status::Unknown, _) | (_, Status::Unknown) => Status::Unknown,
                _ => Status::Failed,
            },
        ),
        Cond::Not(inner) => match eval_cond(inner, root) {
            Status::Passed => Status::Failed,
            Status::Failed => Status::Passed,
            other => other,
        },
        Cond::NoElement { path, where_cond } => eval_no_element(root, path, where_cond),
        Cond::ForbidResource => Status::Failed,
    }
}

fn eval_no_element(root: &Value, path: &AttrPath, where_cond: &Cond) -> Status {
    let resolved = lookup_path(root, path);
    if resolved.values.is_empty() {
        return if resolved.unknown {
            Status::Unknown
        } else {
            Status::Passed
        };
    }
    let mut unknown = resolved.unknown;
    for value in elements_of(&resolved.values) {
        if matches!(value, Value::Unknown { .. }) {
            unknown = true;
            continue;
        }
        match eval_cond(where_cond, value) {
            Status::Passed => return Status::Failed,
            Status::Unknown => unknown = true,
            Status::Failed | Status::Skipped => {}
        }
    }
    if unknown {
        Status::Unknown
    } else {
        Status::Passed
    }
}

fn elements_of<'a>(values: &[&'a Value]) -> Vec<&'a Value> {
    if values.len() == 1 {
        if let Value::Array(items) = values[0] {
            return items.iter().collect();
        }
        if let Value::Object(map) = values[0] {
            return map.values().collect();
        }
    }
    values.to_vec()
}

fn eval_attribute(
    root: &Value,
    path: &AttrPath,
    operator: Operator,
    expected: Option<&Value>,
    missing_override: Option<Missing>,
    regex: Option<&regex::Regex>,
) -> Status {
    let resolved = lookup_path(root, path);
    let missing_behavior = missing_override.unwrap_or_else(|| operator.default_missing());
    if operator == Operator::Exists {
        return exists_status(&resolved, missing_behavior);
    }
    if operator == Operator::NotExists {
        return match exists_status(&resolved, Missing::Fail) {
            Status::Passed => Status::Failed,
            Status::Failed => Status::Passed,
            other => other,
        };
    }
    if resolved.unknown && resolved.values.is_empty() {
        return Status::Unknown;
    }
    if resolved.values.is_empty() {
        return missing_to_status(missing_behavior);
    }

    let mut saw_unknown = resolved.unknown;
    let mut saw_value = false;
    for value in &resolved.values {
        if matches!(value, Value::Unknown { .. }) {
            saw_unknown = true;
            continue;
        }
        saw_value = true;
        let matched = leaf_matches(operator, value, expected, regex);
        let all = !matches!(operator, Operator::EqualsAny | Operator::Intersects);
        if all && !matched {
            return Status::Failed;
        }
        if !all && matched {
            return Status::Passed;
        }
    }
    if !saw_value {
        return if saw_unknown {
            Status::Unknown
        } else {
            missing_to_status(missing_behavior)
        };
    }
    if matches!(operator, Operator::EqualsAny | Operator::Intersects) {
        return if saw_unknown {
            Status::Unknown
        } else {
            Status::Failed
        };
    }
    if saw_unknown {
        return Status::Unknown;
    }
    if resolved.missing {
        return missing_to_status(missing_behavior);
    }
    Status::Passed
}

fn exists_status(resolved: &rustmaninoff_ir::Resolved<'_>, missing: Missing) -> Status {
    let present = resolved.values.iter().any(|value| !value.is_null());
    if present && resolved.unknown {
        return Status::Unknown;
    }
    if present {
        return Status::Passed;
    }
    if resolved.unknown {
        return Status::Unknown;
    }
    missing_to_status(missing)
}

fn missing_to_status(missing: Missing) -> Status {
    match missing {
        Missing::Pass => Status::Passed,
        Missing::Fail => Status::Failed,
        Missing::Unknown => Status::Unknown,
    }
}

fn leaf_matches(
    operator: Operator,
    value: &Value,
    expected: Option<&Value>,
    regex: Option<&regex::Regex>,
) -> bool {
    match operator {
        Operator::Equals => values_equal(value, expected.unwrap_or(&Value::Null)),
        Operator::NotEquals => !values_equal(value, expected.unwrap_or(&Value::Null)),
        Operator::EqualsAny => any_equals(value, expected.unwrap_or(&Value::Null)),
        Operator::Contains => contains(value, expected.unwrap_or(&Value::Null)),
        Operator::NotContains => !contains(value, expected.unwrap_or(&Value::Null)),
        Operator::Within => within(value, expected),
        Operator::NotWithin => !within(value, expected),
        Operator::RegexMatch => regex_match(value, regex, true),
        Operator::NotRegexMatch => regex_match(value, regex, false),
        Operator::StartingWith => string_affix(value, expected, true, true),
        Operator::NotStartingWith => string_affix(value, expected, true, false),
        Operator::EndingWith => string_affix(value, expected, false, true),
        Operator::NotEndingWith => string_affix(value, expected, false, false),
        Operator::GreaterThan => numeric_cmp(value, expected, |left, right| left > right),
        Operator::GreaterThanOrEqual => numeric_cmp(value, expected, |left, right| left >= right),
        Operator::LessThan => numeric_cmp(value, expected, |left, right| left < right),
        Operator::LessThanOrEqual => numeric_cmp(value, expected, |left, right| left <= right),
        Operator::IsEmpty => is_empty(value),
        Operator::IsNotEmpty => !is_empty(value),
        Operator::IsTrue => is_bool(value, true),
        Operator::IsFalse => is_bool(value, false),
        Operator::LengthEquals => length_cmp(value, expected, |left, right| left == right),
        Operator::LengthGreaterThan => length_cmp(value, expected, |left, right| left > right),
        Operator::LengthGreaterThanOrEqual => {
            length_cmp(value, expected, |left, right| left >= right)
        }
        Operator::LengthLessThan => length_cmp(value, expected, |left, right| left < right),
        Operator::LengthLessThanOrEqual => length_cmp(value, expected, |left, right| left <= right),
        Operator::Intersects => intersects(value, expected),
        Operator::NotIntersects => !intersects(value, expected),
        Operator::Any => !matches!(value, Value::Null | Value::Unknown { .. }),
        Operator::ImageTagPinned => image_tag_pinned(value),
        Operator::Exists | Operator::NotExists => false,
    }
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (unwrap_single(left), unwrap_single(right)) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64() && a.as_f64().is_some(),
        (Value::String(a), Value::Bool(b)) => {
            a.eq_ignore_ascii_case(if *b { "true" } else { "false" })
        }
        (Value::Bool(a), Value::String(b)) => {
            b.eq_ignore_ascii_case(if *a { "true" } else { "false" })
        }
        (Value::String(a), Value::Number(b)) => a.parse::<f64>().ok() == b.as_f64(),
        (Value::Number(a), Value::String(b)) => b.parse::<f64>().ok() == a.as_f64(),
        (a, b) => a == b,
    }
}

fn unwrap_single(value: &Value) -> &Value {
    match value {
        Value::Array(items) if items.len() == 1 => &items[0],
        other => other,
    }
}

fn any_equals(value: &Value, expected: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(|item| any_equals(item, expected)),
        other => values_equal(other, expected),
    }
}

fn contains(value: &Value, expected: &Value) -> bool {
    match unwrap_single(value) {
        Value::String(text) => expected
            .as_str()
            .map(|needle| text.contains(needle))
            .unwrap_or(false),
        Value::Array(items) => items.iter().any(|item| {
            values_equal(item, expected)
                || contains(item, expected) && !matches!(item, Value::String(_))
        }),
        other => values_equal(other, expected),
    }
}

fn within(value: &Value, expected: Option<&Value>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let candidates: Vec<&Value> = match expected {
        Value::Array(items) => items.iter().collect(),
        other => vec![other],
    };
    match unwrap_single(value) {
        Value::Array(items) => items.iter().all(|item| {
            candidates
                .iter()
                .any(|candidate| values_equal(item, candidate))
        }),
        other => candidates
            .iter()
            .any(|candidate| values_equal(other, candidate)),
    }
}

fn regex_match(value: &Value, regex: Option<&regex::Regex>, positive: bool) -> bool {
    let Some(regex) = regex else {
        return !positive;
    };
    let matched = match unwrap_single(value) {
        Value::String(text) => regex.is_match(text),
        Value::Array(items) => items.iter().all(|item| {
            item.as_str()
                .map(|text| regex.is_match(text))
                .unwrap_or(false)
        }),
        _ => false,
    };
    if positive {
        matched
    } else {
        !matched
    }
}

fn string_affix(value: &Value, expected: Option<&Value>, prefix: bool, positive: bool) -> bool {
    let Some(needle) = expected.and_then(Value::as_str) else {
        return !positive;
    };
    let matched = match unwrap_single(value) {
        Value::String(text) => {
            if prefix {
                text.starts_with(needle)
            } else {
                text.ends_with(needle)
            }
        }
        _ => false,
    };
    if positive {
        matched
    } else {
        !matched
    }
}

fn numeric_cmp(value: &Value, expected: Option<&Value>, cmp: impl Fn(f64, f64) -> bool) -> bool {
    let Some(right) = expected.and_then(Value::as_f64) else {
        return false;
    };
    unwrap_single(value)
        .as_f64()
        .map(|left| cmp(left, right))
        .unwrap_or(false)
}

fn is_empty(value: &Value) -> bool {
    match unwrap_single(value) {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn is_bool(value: &Value, expected: bool) -> bool {
    match unwrap_single(value) {
        Value::Bool(value) => *value == expected,
        Value::String(text) => text.eq_ignore_ascii_case(if expected { "true" } else { "false" }),
        _ => false,
    }
}

fn length_of(value: &Value) -> Option<f64> {
    match unwrap_single(value) {
        Value::String(text) => Some(text.chars().count() as f64),
        Value::Array(items) => Some(items.len() as f64),
        Value::Object(map) => Some(map.len() as f64),
        _ => None,
    }
}

fn length_cmp(value: &Value, expected: Option<&Value>, cmp: impl Fn(f64, f64) -> bool) -> bool {
    let Some(right) = expected.and_then(Value::as_f64) else {
        return false;
    };
    length_of(value)
        .map(|left| cmp(left, right))
        .unwrap_or(false)
}

fn intersects(value: &Value, expected: Option<&Value>) -> bool {
    let mut haystack = Vec::new();
    collect_strings(value, &mut haystack);
    if haystack.iter().any(|item| item == "*" || item == "*:*") {
        return expected.is_some();
    }
    let Some(expected) = expected else {
        return false;
    };
    let mut needles = Vec::new();
    collect_strings(expected, &mut needles);
    haystack
        .iter()
        .any(|item| needles.iter().any(|needle| item == needle))
}

fn collect_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => out.push(text.clone()),
        Value::Number(number) => out.push(number.to_string()),
        Value::Bool(value) => out.push(value.to_string()),
        Value::Array(items) => {
            for item in items {
                collect_strings(item, out);
            }
        }
        _ => {}
    }
}

fn image_tag_pinned(value: &Value) -> bool {
    let Some(image) = unwrap_single(value).as_str() else {
        return false;
    };
    if image.contains('@') {
        return true;
    }
    let name = image.rsplit('/').next().unwrap_or(image);
    match name.rsplit_once(':') {
        Some((_, tag)) => !tag.is_empty() && !tag.eq_ignore_ascii_case("latest"),
        None => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub check_id: std::sync::Arc<str>,
    pub check_name: std::sync::Arc<str>,
    pub category: std::sync::Arc<str>,
    pub severity: Severity,
    pub status: Status,
    pub resource_address: std::sync::Arc<str>,
    pub resource_type: std::sync::Arc<str>,
    pub resource_name: std::sync::Arc<str>,
    pub framework: std::sync::Arc<str>,
    pub file: std::sync::Arc<str>,
    pub start_line: usize,
    pub end_line: usize,
    pub guidelines: Option<std::sync::Arc<str>>,
    pub skip_reason: Option<String>,
}
