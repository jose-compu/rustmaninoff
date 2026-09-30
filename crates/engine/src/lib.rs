//! Checkov-compatible attribute policy engine.

mod eval;
mod policy;

pub use eval::{eval_cond, Cond, Finding, Status};
pub use policy::{load_policy_dir, parse_policy, Policy, PolicyError, Severity};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use rayon::prelude::*;
use rustmaninoff_ir::{Framework, Resource};

/// Evaluate `policies` against `resources`.
///
/// Results that share a check id and resource are collapsed to the worst status,
/// so a security group and its rule form can share one Checkov id.
pub fn evaluate(resources: &[Resource], policies: &[Policy]) -> Vec<Finding> {
    if resources.is_empty() || policies.is_empty() {
        return Vec::new();
    }
    let index = PolicyIndex::build(policies);
    let findings = if resources.len() < 32 {
        resources
            .iter()
            .flat_map(|resource| eval_resource(resource, &index))
            .collect()
    } else {
        resources
            .par_iter()
            .flat_map(|resource| eval_resource(resource, &index))
            .collect()
    };
    collapse(findings)
}

struct PolicyIndex<'a> {
    exact: HashMap<Framework, HashMap<String, Vec<&'a Policy>>>,
    wild: HashMap<Framework, Vec<&'a Policy>>,
    unscoped_exact: HashMap<String, Vec<&'a Policy>>,
    unscoped_wild: Vec<&'a Policy>,
}

impl<'a> PolicyIndex<'a> {
    fn build(policies: &'a [Policy]) -> Self {
        let mut index = Self {
            exact: HashMap::new(),
            wild: HashMap::new(),
            unscoped_exact: HashMap::new(),
            unscoped_wild: Vec::new(),
        };
        for policy in policies {
            let wild = policy
                .resource_types
                .iter()
                .any(|resource_type| resource_type == "*" || resource_type == "all");
            match policy.framework {
                Some(framework) => {
                    if wild {
                        index.wild.entry(framework).or_default().push(policy);
                    }
                    for resource_type in &policy.resource_types {
                        if resource_type == "*" || resource_type == "all" {
                            continue;
                        }
                        index
                            .exact
                            .entry(framework)
                            .or_default()
                            .entry(resource_type.clone())
                            .or_default()
                            .push(policy);
                    }
                }
                None => {
                    if wild {
                        index.unscoped_wild.push(policy);
                    }
                    for resource_type in &policy.resource_types {
                        if resource_type == "*" || resource_type == "all" {
                            continue;
                        }
                        index
                            .unscoped_exact
                            .entry(resource_type.clone())
                            .or_default()
                            .push(policy);
                    }
                }
            }
        }
        index
    }
}

fn eval_resource(resource: &Resource, index: &PolicyIndex<'_>) -> Vec<Finding> {
    let shared = SharedIds {
        address: Arc::from(format!("{}.{}", resource.resource_type, resource.name)),
        file: Arc::from(resource.file.display().to_string()),
        resource_type: Arc::from(resource.resource_type.as_str()),
        resource_name: Arc::from(resource.name.as_str()),
        framework: Arc::from(resource.framework.as_str()),
    };
    let mut findings = Vec::new();
    let mut visit = |policy: &Policy| {
        if let Some(skip) = resource
            .skips
            .iter()
            .find(|skip| skip.check_id == policy.id.as_ref())
        {
            findings.push(make_finding(
                policy,
                Status::Skipped,
                &shared,
                resource,
                skip.reason.clone(),
            ));
            return;
        }
        let status = eval_cond(&policy.definition, &resource.attributes);
        findings.push(make_finding(policy, status, &shared, resource, None));
    };
    if let Some(by_type) = index.exact.get(&resource.framework) {
        if let Some(list) = by_type.get(resource.resource_type.as_str()) {
            for policy in list {
                visit(policy);
            }
        }
    }
    if let Some(list) = index.wild.get(&resource.framework) {
        for policy in list {
            visit(policy);
        }
    }
    if let Some(list) = index.unscoped_exact.get(resource.resource_type.as_str()) {
        for policy in list {
            visit(policy);
        }
    }
    for policy in &index.unscoped_wild {
        visit(policy);
    }
    findings
}

struct SharedIds {
    address: Arc<str>,
    file: Arc<str>,
    resource_type: Arc<str>,
    resource_name: Arc<str>,
    framework: Arc<str>,
}

fn make_finding(
    policy: &Policy,
    status: Status,
    shared: &SharedIds,
    resource: &Resource,
    skip_reason: Option<String>,
) -> Finding {
    Finding {
        check_id: Arc::clone(&policy.id),
        check_name: Arc::clone(&policy.name),
        category: Arc::clone(&policy.category),
        severity: policy.severity,
        status,
        resource_address: Arc::clone(&shared.address),
        resource_type: Arc::clone(&shared.resource_type),
        resource_name: Arc::clone(&shared.resource_name),
        framework: Arc::clone(&shared.framework),
        file: Arc::clone(&shared.file),
        start_line: resource.start_line,
        end_line: resource.end_line,
        guidelines: policy.guidelines.clone(),
        skip_reason,
    }
}

type FindingKey = (Arc<str>, Arc<str>, Arc<str>);

fn collapse(findings: Vec<Finding>) -> Vec<Finding> {
    let mut grouped: BTreeMap<FindingKey, Finding> = BTreeMap::new();
    for finding in findings {
        let key = (
            Arc::clone(&finding.check_id),
            Arc::clone(&finding.file),
            Arc::clone(&finding.resource_address),
        );
        match grouped.get(&key) {
            Some(existing) if existing.status >= finding.status => {}
            _ => {
                grouped.insert(key, finding);
            }
        }
    }
    grouped.into_values().collect()
}

#[cfg(test)]
mod coverage;

#[cfg(test)]
mod tests {
    use super::*;
    use rustmaninoff_ir::{Framework, Value};
    use std::path::PathBuf;

    fn resource(resource_type: &str, name: &str, attributes: Value) -> Resource {
        Resource {
            framework: Framework::Terraform,
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            attributes,
            file: PathBuf::from("main.tf"),
            start_line: 1,
            end_line: 4,
            skips: Vec::new(),
        }
    }

    fn policy(yaml: &str) -> Policy {
        parse_policy(yaml).expect("policy")
    }

    #[test]
    fn equals_true_fails_when_false() {
        let policy = policy(
            r#"
metadata:
  id: CKV_AWS_3
  name: encrypted
  severity: HIGH
  framework: terraform
resource_types:
  - aws_ebs_volume
definition:
  cond_type: attribute
  attribute: encrypted
  operator: equals
  value: true
"#,
        );
        let bad = resource(
            "aws_ebs_volume",
            "bad",
            Value::Object(
                [("encrypted".into(), Value::Bool(false))]
                    .into_iter()
                    .collect(),
            ),
        );
        let findings = evaluate(&[bad], &[policy]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, Status::Failed);
    }

    #[test]
    fn unknown_does_not_fail() {
        let policy = policy(
            r#"
metadata:
  id: CKV_AWS_3
  name: encrypted
  severity: HIGH
  framework: terraform
resource_types: [aws_ebs_volume]
definition:
  cond_type: attribute
  attribute: encrypted
  operator: equals
  value: true
"#,
        );
        let unknown = resource(
            "aws_ebs_volume",
            "x",
            Value::Object(
                [(
                    "encrypted".into(),
                    Value::Unknown {
                        expr: "var.x".into(),
                    },
                )]
                .into_iter()
                .collect(),
            ),
        );
        let findings = evaluate(&[unknown], &[policy]);
        assert_eq!(findings[0].status, Status::Unknown);
    }

    #[test]
    fn no_element_detects_open_ingress() {
        let policy = policy(
            r#"
metadata:
  id: CKV_AWS_24
  name: ssh
  severity: HIGH
  framework: terraform
resource_types: [aws_security_group]
definition:
  cond_type: no_element
  attribute: ingress
  where:
    and:
      - cond_type: attribute
        attribute: from_port
        operator: less_than_or_equal
        value: 22
      - cond_type: attribute
        attribute: to_port
        operator: greater_than_or_equal
        value: 22
      - cond_type: attribute
        attribute: cidr_blocks
        operator: contains
        value: "0.0.0.0/0"
"#,
        );
        let bad = resource(
            "aws_security_group",
            "bad",
            Value::from_json(serde_json::json!({
                "ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]
            })),
        );
        let good = resource(
            "aws_security_group",
            "good",
            Value::from_json(serde_json::json!({
                "ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["0.0.0.0/0"]}]
            })),
        );
        assert_eq!(
            evaluate(&[bad], std::slice::from_ref(&policy))[0].status,
            Status::Failed
        );
        assert_eq!(evaluate(&[good], &[policy])[0].status, Status::Passed);
    }

    #[test]
    fn numeric_comparisons_agree_with_integers() {
        let policy = policy(
            r#"
metadata:
  id: NUM
  name: length
  framework: terraform
resource_types: [aws_iam_account_password_policy]
definition:
  cond_type: attribute
  attribute: minimum_password_length
  operator: greater_than_or_equal
  value: 14
"#,
        );
        for length in 0..40 {
            let resource = resource(
                "aws_iam_account_password_policy",
                "p",
                Value::from_json(serde_json::json!({"minimum_password_length": length})),
            );
            let status = evaluate(&[resource], std::slice::from_ref(&policy))[0].status;
            if length >= 14 {
                assert_eq!(status, Status::Passed, "{length}");
            } else {
                assert_eq!(status, Status::Failed, "{length}");
            }
        }
    }
}
