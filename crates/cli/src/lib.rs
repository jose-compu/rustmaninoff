//! Rustmaninoff scans Terraform, CloudFormation, and Kubernetes for misconfigurations.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use clap::Parser;
use include_dir::{include_dir, Dir};
use rayon::prelude::*;
use rustmaninoff_engine::{evaluate, load_policy_dir, Policy, PolicyError, Severity};
use rustmaninoff_ir::{
    input_limit, Diagnostic, Framework, ParseOutput, MAX_POLICY_BYTES, MAX_SOURCE_BYTES,
};
use rustmaninoff_report::{render_json, render_junit, render_sarif, render_text, RenderOptions};
use serde::Deserialize;

static POLICIES: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/policies");

const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    ".terraform",
    ".terragrunt-cache",
    "node_modules",
    "vendor",
    "target",
];

#[derive(Debug, Parser)]
#[command(name = "rustmaninoff", version, about = "Fast IaC security scanner")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    /// Scan a directory or file for misconfigurations.
    Scan(ScanArgs),
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Directory or file to scan. Defaults to the current directory.
    pub path: Option<PathBuf>,
    /// Comma-separated frameworks: terraform,cloudformation,kubernetes.
    #[arg(long)]
    pub framework: Option<String>,
    /// Comma-separated check ids to run.
    #[arg(long)]
    pub check: Option<String>,
    /// Comma-separated check ids to skip.
    #[arg(long)]
    pub skip_check: Option<String>,
    /// Config file. Defaults to .rustmaninoff.yaml in the scan path.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Comma-separated outputs: cli,json,sarif,junit.
    #[arg(long, default_value = "cli")]
    pub output: String,
    #[arg(long)]
    pub json_file: Option<PathBuf>,
    #[arg(long)]
    pub sarif_file: Option<PathBuf>,
    #[arg(long)]
    pub junit_file: Option<PathBuf>,
    /// Minimum severity that fails the process: LOW, MEDIUM, HIGH, CRITICAL.
    #[arg(long)]
    pub fail_on: Option<String>,
    /// Directory of extra YAML policies. Repeatable.
    #[arg(long = "external-checks-dir")]
    pub external_checks_dir: Vec<PathBuf>,
    #[arg(long)]
    pub show_unknown: bool,
    #[arg(long)]
    pub compact: bool,
    /// Report findings and return exit code 0.
    #[arg(long)]
    pub soft_fail: bool,
    /// Print passed checks in the text report.
    #[arg(long)]
    pub show_passed: bool,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    #[serde(default)]
    frameworks: Option<Vec<String>>,
    #[serde(default)]
    skip_checks: Vec<String>,
    #[serde(default)]
    fail_on: Option<String>,
    #[serde(default)]
    excluded_paths: Vec<String>,
    #[serde(default)]
    external_checks_dirs: Vec<PathBuf>,
    #[serde(default)]
    show_unknown: bool,
    #[serde(default)]
    compact: bool,
}

#[derive(Clone, Debug)]
pub struct ScanRequest {
    pub path: PathBuf,
    pub frameworks: Vec<Framework>,
    pub checks: Vec<String>,
    pub skip_checks: Vec<String>,
    pub fail_on: Severity,
    pub external_dirs: Vec<PathBuf>,
    pub show_unknown: bool,
    pub show_passed: bool,
    pub compact: bool,
    pub soft_fail: bool,
    pub outputs: Vec<String>,
    pub json_file: Option<PathBuf>,
    pub sarif_file: Option<PathBuf>,
    pub junit_file: Option<PathBuf>,
    pub excluded: Vec<String>,
}

pub struct ScanResult {
    pub findings: Vec<rustmaninoff_engine::Finding>,
    pub diagnostics: Vec<Diagnostic>,
    pub exit_code: i32,
}

pub fn execute(cli: Cli) -> anyhow::Result<i32> {
    match cli.command {
        Command::Scan(args) => {
            let request = request_from_args(args)?;
            let result = scan(&request)?;
            emit(&request, &result)?;
            Ok(result.exit_code)
        }
    }
}

pub fn scan(request: &ScanRequest) -> anyhow::Result<ScanResult> {
    let files = discover(&request.path, &request.excluded);
    let parsed: Vec<ParseOutput> = files
        .par_iter()
        .filter_map(|path| classify_and_parse(path, &request.frameworks))
        .collect();
    let mut resources = Vec::new();
    let mut diagnostics = Vec::new();
    for output in parsed {
        resources.extend(output.resources);
        diagnostics.extend(output.diagnostics);
    }
    let policies = select_policies(request)?;
    let findings = evaluate(&resources, policies.as_ref());
    let failing = findings.iter().any(|finding| {
        finding.status == rustmaninoff_engine::Status::Failed && finding.severity >= request.fail_on
    });
    let exit_code = if request.soft_fail {
        0
    } else if failing || !diagnostics.is_empty() {
        1
    } else {
        0
    };
    Ok(ScanResult {
        findings,
        diagnostics,
        exit_code,
    })
}

fn request_from_args(args: ScanArgs) -> anyhow::Result<ScanRequest> {
    let raw_path = args.path.clone().unwrap_or_else(|| PathBuf::from("."));
    let path = raw_path.canonicalize().unwrap_or(raw_path);
    let config = load_config(args.config.as_deref(), &path)?;
    let frameworks = match &args.framework {
        Some(value) => parse_frameworks(value)?,
        None => match config.as_ref().and_then(|item| item.frameworks.clone()) {
            Some(values) => values
                .iter()
                .map(|value| {
                    Framework::parse(value)
                        .ok_or_else(|| anyhow::anyhow!("unknown framework '{value}'"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?,
            None => vec![
                Framework::Terraform,
                Framework::CloudFormation,
                Framework::Kubernetes,
            ],
        },
    };
    let fail_on = args
        .fail_on
        .as_deref()
        .or_else(|| config.as_ref().and_then(|item| item.fail_on.as_deref()))
        .unwrap_or("HIGH");
    let fail_on =
        Severity::parse(fail_on).ok_or_else(|| anyhow::anyhow!("unknown severity '{fail_on}'"))?;
    let mut skip_checks = config
        .as_ref()
        .map(|item| item.skip_checks.clone())
        .unwrap_or_default();
    if let Some(value) = &args.skip_check {
        skip_checks.extend(split_csv(value));
    }
    let mut external_dirs = config
        .as_ref()
        .map(|item| item.external_checks_dirs.clone())
        .unwrap_or_default();
    external_dirs.extend(args.external_checks_dir);
    let mut excluded = DEFAULT_EXCLUDES
        .iter()
        .map(|item| (*item).to_string())
        .collect::<Vec<_>>();
    if let Some(config) = &config {
        excluded.extend(config.excluded_paths.clone());
    }
    Ok(ScanRequest {
        path,
        frameworks,
        checks: args.check.as_deref().map(split_csv).unwrap_or_default(),
        skip_checks,
        fail_on,
        external_dirs,
        show_unknown: args.show_unknown || config.as_ref().is_some_and(|item| item.show_unknown),
        show_passed: args.show_passed,
        compact: args.compact || config.as_ref().is_some_and(|item| item.compact),
        soft_fail: args.soft_fail,
        outputs: split_csv(&args.output),
        json_file: args.json_file,
        sarif_file: args.sarif_file,
        junit_file: args.junit_file,
        excluded,
    })
}

fn load_config(explicit: Option<&Path>, scan_path: &Path) -> anyhow::Result<Option<FileConfig>> {
    let path = if let Some(explicit) = explicit {
        explicit.to_path_buf()
    } else {
        let candidate = scan_path.join(".rustmaninoff.yaml");
        if candidate.is_file() {
            candidate
        } else {
            return Ok(None);
        }
    };
    let meta = fs::symlink_metadata(&path)
        .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!("refusing to read symlink config {}", path.display());
    }
    if meta.len() > MAX_POLICY_BYTES {
        anyhow::bail!("config {} exceeds 1MB", path.display());
    }
    let text = fs::read_to_string(&path)
        .map_err(|err| anyhow::anyhow!("failed to read {}: {err}", path.display()))?;
    if let Some(message) = input_limit(&text) {
        anyhow::bail!("config {}: {message}", path.display());
    }
    let config = serde_yaml::from_str(&text)
        .map_err(|err| anyhow::anyhow!("invalid config {}: {err}", path.display()))?;
    Ok(Some(config))
}

fn parse_frameworks(value: &str) -> anyhow::Result<Vec<Framework>> {
    split_csv(value)
        .into_iter()
        .map(|item| {
            Framework::parse(&item).ok_or_else(|| anyhow::anyhow!("unknown framework '{item}'"))
        })
        .collect()
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

fn discover(root: &Path, excluded: &[String]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    walk(root, excluded, &mut files);
    files
}

fn walk(dir: &Path, excluded: &[String], out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if excluded.iter().any(|item| item == name.as_ref()) {
            continue;
        }
        if file_type.is_dir() {
            walk(&path, excluded, out);
        } else if file_type.is_file() && is_candidate(&path) {
            out.push(path);
        }
    }
}

fn is_candidate(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("tf" | "json" | "yaml" | "yml") => true,
        _ => path.to_string_lossy().ends_with(".tf.json"),
    }
}

fn classify_and_parse(path: &Path, frameworks: &[Framework]) -> Option<ParseOutput> {
    let meta = fs::symlink_metadata(path).ok()?;
    let file_type = meta.file_type();
    if file_type.is_symlink() || !file_type.is_file() {
        return None;
    }
    if meta.len() > MAX_SOURCE_BYTES {
        return Some(skipped_file(path, "file exceeds 10MB and was skipped"));
    }
    let source = fs::read_to_string(path).ok()?;
    if source.len() as u64 > MAX_SOURCE_BYTES {
        return Some(skipped_file(path, "file exceeds 10MB and was skipped"));
    }
    if let Some(message) = input_limit(&source) {
        return Some(skipped_file(path, message));
    }
    let kind = detect(path, &source)?;
    if !frameworks.contains(&kind) {
        return None;
    }
    let output = match kind {
        Framework::Terraform => rustmaninoff_parser_terraform::parse_file(path, &source),
        Framework::CloudFormation => rustmaninoff_parser_cfn::parse_file(path, &source),
        Framework::Kubernetes => rustmaninoff_parser_k8s::parse_file(path, &source),
    };
    Some(output)
}

fn skipped_file(path: &Path, message: &str) -> ParseOutput {
    ParseOutput {
        resources: Vec::new(),
        diagnostics: vec![Diagnostic {
            file: path.to_path_buf(),
            line: 1,
            message: message.to_string(),
        }],
    }
}

fn detect(path: &Path, source: &str) -> Option<Framework> {
    let name = path.to_string_lossy();
    if name.ends_with(".tf") || name.ends_with(".tf.json") {
        return Some(Framework::Terraform);
    }
    let trimmed = source.trim_start();
    if trimmed.contains("AWSTemplateFormatVersion") || has_cfn_resources(trimmed) {
        return Some(Framework::CloudFormation);
    }
    if trimmed.contains("\nkind:")
        || trimmed.starts_with("kind:")
        || trimmed.contains("apiVersion:")
    {
        return Some(Framework::Kubernetes);
    }
    if name.ends_with(".json") && trimmed.contains("\"resource\"") {
        return Some(Framework::Terraform);
    }
    None
}

fn has_cfn_resources(source: &str) -> bool {
    source.contains("\nResources:")
        || source.starts_with("Resources:")
        || source.contains("\"Resources\"")
}

pub fn builtin_policies() -> Result<Vec<Policy>, PolicyError> {
    Ok(shared_policies()?.to_vec())
}

fn shared_policies() -> Result<&'static [Policy], PolicyError> {
    static CACHE: OnceLock<Result<Vec<Policy>, String>> = OnceLock::new();
    match CACHE.get_or_init(load_builtin_policies) {
        Ok(policies) => Ok(policies.as_slice()),
        Err(err) => Err(PolicyError::Invalid(err.clone())),
    }
}

fn load_builtin_policies() -> Result<Vec<Policy>, String> {
    let mut policies = Vec::new();
    collect_embedded(&POLICIES, &mut policies).map_err(|err| err.to_string())?;
    policies.sort_by(|left, right| left.id.cmp(&right.id).then(left.name.cmp(&right.name)));
    Ok(policies)
}

fn select_policies(request: &ScanRequest) -> anyhow::Result<std::borrow::Cow<'static, [Policy]>> {
    let shared = shared_policies().map_err(|err| anyhow::anyhow!(err.to_string()))?;
    if request.external_dirs.is_empty()
        && request.checks.is_empty()
        && request.skip_checks.is_empty()
    {
        return Ok(std::borrow::Cow::Borrowed(shared));
    }
    let mut policies = shared.to_vec();
    for dir in &request.external_dirs {
        policies.extend(load_policy_dir(dir).map_err(|err| anyhow::anyhow!(err.to_string()))?);
    }
    if !request.checks.is_empty() {
        policies.retain(|policy| {
            request
                .checks
                .iter()
                .any(|id| policy.id.as_ref() == id.as_str())
        });
    }
    if !request.skip_checks.is_empty() {
        policies.retain(|policy| {
            !request
                .skip_checks
                .iter()
                .any(|id| policy.id.as_ref() == id.as_str())
        });
    }
    Ok(std::borrow::Cow::Owned(policies))
}

fn collect_embedded(dir: &Dir<'_>, out: &mut Vec<Policy>) -> Result<(), PolicyError> {
    for entry in dir.entries() {
        match entry {
            include_dir::DirEntry::Dir(child) => collect_embedded(child, out)?,
            include_dir::DirEntry::File(file) => {
                let path = file.path();
                let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
                if ext != "yaml" && ext != "yml" {
                    continue;
                }
                let text = file.contents_utf8().ok_or_else(|| {
                    PolicyError::Invalid(format!("{} is not utf-8", path.display()))
                })?;
                let policy = rustmaninoff_engine::parse_policy(text)
                    .map_err(|err| PolicyError::Invalid(format!("{}: {err}", path.display())))?;
                out.push(policy);
            }
        }
    }
    Ok(())
}

fn emit(request: &ScanRequest, result: &ScanResult) -> anyhow::Result<()> {
    let options = RenderOptions {
        show_passed: request.show_passed,
        show_unknown: request.show_unknown,
        compact: request.compact,
    };
    for output in &request.outputs {
        match output.as_str() {
            "cli" | "text" => {
                print!(
                    "{}",
                    render_text(&result.findings, &result.diagnostics, &options)
                );
            }
            "json" => write_output(
                &render_json(&result.findings, &result.diagnostics),
                request.json_file.as_deref(),
            )?,
            "sarif" => write_output(
                &render_sarif(&result.findings),
                request.sarif_file.as_deref(),
            )?,
            "junit" => write_output(
                &render_junit(&result.findings, &result.diagnostics),
                request.junit_file.as_deref(),
            )?,
            other => anyhow::bail!("unknown output '{other}'"),
        }
    }
    Ok(())
}

fn write_output(text: &str, path: Option<&Path>) -> anyhow::Result<()> {
    match path {
        Some(path) => fs::write(path, text)
            .map_err(|err| anyhow::anyhow!("failed to write {}: {err}", path.display())),
        None => {
            println!("{text}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod coverage;
#[cfg(test)]
mod pack_tests;
#[cfg(test)]
mod safety_tests;
