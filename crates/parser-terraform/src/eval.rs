//! Terraform variable / local evaluation helpers.

use std::collections::BTreeMap;
use std::env;

use hcl::expr::{Expression, Traversal, TraversalOperator};
use hcl::structure::Body;
use rustmaninoff_ir::Value;

/// Values available while resolving Terraform expressions.
#[derive(Clone, Debug, Default)]
pub struct EvalContext {
    pub variables: BTreeMap<String, Value>,
    pub locals: BTreeMap<String, Value>,
}

impl EvalContext {
    pub fn from_env() -> Self {
        let mut ctx = Self::default();
        for (key, value) in env::vars() {
            let Some(name) = key.strip_prefix("TF_VAR_") else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            ctx.variables
                .entry(name.to_string())
                .or_insert_with(|| Value::string(value));
        }
        ctx
    }

    pub fn merge_variables(&mut self, values: BTreeMap<String, Value>) {
        for (key, value) in values {
            self.variables.insert(key, value);
        }
    }

    pub fn resolve_traversal(&self, traversal: &Traversal) -> Option<Value> {
        let Expression::Variable(variable) = &traversal.expr else {
            return None;
        };
        let root = variable.as_str();
        let attrs: Vec<&str> = traversal
            .operators
            .iter()
            .map_while(|op| match op {
                TraversalOperator::GetAttr(ident) => Some(ident.as_str()),
                _ => None,
            })
            .collect();
        match root {
            "var" => {
                let name = attrs.first()?;
                self.variables.get(*name).cloned()
            }
            "local" => {
                let name = attrs.first()?;
                self.locals.get(*name).cloned()
            }
            _ => None,
        }
    }
}

/// Parse a `.tfvars` / `.tfvars.json` body into variable values.
pub fn parse_tfvars(source: &str) -> Result<BTreeMap<String, Value>, String> {
    let trimmed = source.trim_start();
    if trimmed.starts_with('{') {
        let parsed: serde_json::Value =
            serde_json::from_str(source).map_err(|err| err.to_string())?;
        let Some(object) = parsed.as_object() else {
            return Err("tfvars JSON must be an object".into());
        };
        return Ok(object
            .iter()
            .map(|(key, value)| (key.clone(), Value::from_json(value.clone())))
            .collect());
    }
    let body: Body = hcl::from_str(source).map_err(|err| err.to_string())?;
    let mut values = BTreeMap::new();
    for attribute in body.attributes() {
        values.insert(
            attribute.key().to_string(),
            crate::expr_to_value_raw(attribute.expr()),
        );
    }
    Ok(values)
}

pub fn collect_file_context(body: &Body, external: &EvalContext) -> EvalContext {
    let mut ctx = external.clone();
    for block in body.blocks() {
        if block.identifier() != "variable" {
            continue;
        }
        let Some(name) = block.labels().iter().next().map(|label| label.as_str()) else {
            continue;
        };
        if ctx.variables.contains_key(name) {
            continue;
        }
        for attribute in block.body().attributes() {
            if attribute.key() == "default" {
                ctx.variables
                    .insert(name.to_string(), crate::expr_to_value_raw(attribute.expr()));
            }
        }
    }
    for block in body.blocks() {
        if block.identifier() != "locals" {
            continue;
        }
        for attribute in block.body().attributes() {
            let value = crate::expr_to_value_with_ctx(attribute.expr(), &ctx);
            ctx.locals.insert(attribute.key().to_string(), value);
        }
    }
    ctx
}
