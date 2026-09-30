//! Load Checkov-style YAML policies.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use rustmaninoff_ir::{input_limit, Framework, Value, MAX_POLICY_BYTES};
use serde::Deserialize;

use crate::eval::Cond;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("invalid policy: {0}")]
    Invalid(String),
    #[error("failed to read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "low" | "info" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Fixtures {
    pub fail: String,
    pub pass: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub category: Arc<str>,
    pub severity: Severity,
    pub framework: Option<Framework>,
    pub guidelines: Option<Arc<str>>,
    pub resource_types: Vec<String>,
    pub definition: Cond,
    pub fixtures: Option<Fixtures>,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    metadata: RawMetadata,
    #[serde(default)]
    resource_types: YamlStringList,
    definition: serde_yaml::Value,
    #[serde(default)]
    fixtures: Option<RawFixtures>,
    #[serde(default)]
    scope: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    id: String,
    name: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    framework: Option<String>,
    #[serde(default)]
    guidelines: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFixtures {
    fail: String,
    #[serde(rename = "pass")]
    pass_fixture: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum YamlStringList {
    #[default]
    Missing,
    One(String),
    Many(Vec<String>),
}

impl YamlStringList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::Missing => Vec::new(),
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

pub fn parse_policy(text: &str) -> Result<Policy, PolicyError> {
    let raw: RawPolicy =
        serde_yaml::from_str(text).map_err(|err| PolicyError::Invalid(format!("yaml: {err}")))?;
    let _ = raw.scope;
    let mut resource_types = raw.resource_types.into_vec();
    if resource_types.is_empty() {
        resource_types = resource_types_from_definition(&raw.definition);
    }
    if resource_types.is_empty() {
        return Err(PolicyError::Invalid(format!(
            "{} is missing resource_types",
            raw.metadata.id
        )));
    }
    let definition = Cond::from_yaml(&raw.definition)
        .map_err(|err| PolicyError::Invalid(format!("{}: {err}", raw.metadata.id)))?;
    let framework = match raw.metadata.framework {
        Some(value) => Some(Framework::parse(&value).ok_or_else(|| {
            PolicyError::Invalid(format!(
                "unknown framework '{value}' on {}",
                raw.metadata.id
            ))
        })?),
        None => None,
    };
    let severity = match raw.metadata.severity {
        Some(value) => Severity::parse(&value).ok_or_else(|| {
            PolicyError::Invalid(format!("unknown severity '{value}' on {}", raw.metadata.id))
        })?,
        None => Severity::Medium,
    };
    let fixtures = raw.fixtures.map(|fixtures| Fixtures {
        fail: fixtures.fail,
        pass: fixtures.pass_fixture,
    });
    Ok(Policy {
        id: Arc::from(raw.metadata.id),
        name: Arc::from(raw.metadata.name),
        category: Arc::from(
            raw.metadata
                .category
                .unwrap_or_else(|| "GENERAL_SECURITY".to_string()),
        ),
        severity,
        framework,
        guidelines: raw.metadata.guidelines.map(Arc::from),
        resource_types,
        definition,
        fixtures,
    })
}

fn resource_types_from_definition(value: &serde_yaml::Value) -> Vec<String> {
    let Some(map) = value.as_mapping() else {
        return Vec::new();
    };
    for (key, item) in map {
        if key.as_str() == Some("resource_types") {
            return string_list(item);
        }
    }
    Vec::new()
}

fn string_list(value: &serde_yaml::Value) -> Vec<String> {
    if let Some(text) = value.as_str() {
        return vec![text.to_string()];
    }
    value
        .as_sequence()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

pub fn load_policy_dir(path: &Path) -> Result<Vec<Policy>, PolicyError> {
    let mut policies = Vec::new();
    load_dir(path, &mut policies)?;
    policies.sort_by(|left, right| {
        (
            &left.id,
            &left.name,
            left.framework.map(|item| item.as_str()),
        )
            .cmp(&(
                &right.id,
                &right.name,
                right.framework.map(|item| item.as_str()),
            ))
    });
    Ok(policies)
}

fn load_dir(path: &Path, out: &mut Vec<Policy>) -> Result<(), PolicyError> {
    let entries = fs::read_dir(path).map_err(|source| PolicyError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut paths: Vec<_> =
        entries
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PolicyError::Io {
                path: path.display().to_string(),
                source,
            })?;
    paths.sort_by_key(|entry| entry.path());
    for entry in paths {
        let child = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            load_dir(&child, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let Some(ext) = child.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if ext != "yaml" && ext != "yml" {
            continue;
        }
        let meta = fs::symlink_metadata(&child).map_err(|source| PolicyError::Io {
            path: child.display().to_string(),
            source,
        })?;
        if meta.len() > MAX_POLICY_BYTES {
            return Err(PolicyError::Invalid(format!(
                "{} exceeds 1MB",
                child.display()
            )));
        }
        let text = fs::read_to_string(&child).map_err(|source| PolicyError::Io {
            path: child.display().to_string(),
            source,
        })?;
        if let Some(message) = input_limit(&text) {
            return Err(PolicyError::Invalid(format!(
                "{}: {message}",
                child.display()
            )));
        }
        let policy = parse_policy(&text)
            .map_err(|err| PolicyError::Invalid(format!("{}: {err}", child.display())))?;
        out.push(policy);
    }
    Ok(())
}

pub fn yaml_to_value(value: &serde_yaml::Value) -> Value {
    Value::from_yaml(value.clone())
}
