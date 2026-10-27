// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cedar-authored sandbox policies (`cedar_policy_source`).
//!
//! Built only with the `cedar` feature. Validation, load-time warnings,
//! filesystem-grant derivation, and provider-rule adaptation for Cedar
//! policies all go through this module; builds without the feature reject
//! Cedar policies instead.

use std::collections::{BTreeMap, HashMap};
use std::hash::BuildHasher;

use miette::Result;
use openshell_core::proto::{
    FilesystemPolicy, NetworkEndpoint, NetworkPolicyRule, NetworkTlsMode, SandboxPolicy,
};
use openshell_policy_cedar::{
    CedarEngine, ProviderEndpoint, ProviderPolicy, RuleMatcher, TokenGrantRules, ValueMatcher,
};
use serde_json::Value;

use crate::{EffectiveFilesystem, PolicyViolation};

fn load(cedar_policy_source: &str) -> std::result::Result<CedarEngine, PolicyViolation> {
    CedarEngine::from_policy_str(cedar_policy_source).map_err(|error| {
        PolicyViolation::InvalidCedarPolicy {
            reason: error.to_string(),
        }
    })
}

/// Checks that the Cedar engine accepts `cedar_policy_source`, that its
/// Landlock grants pass the same path checks as YAML `filesystem` paths, and
/// that no `endpoint_settings` entry skips TLS on an endpoint it inspects,
/// returning its load-time warnings.
pub(crate) fn validate(
    cedar_policy_source: &str,
    endpoint_settings: &[NetworkEndpoint],
    violations: &mut Vec<PolicyViolation>,
) -> Vec<String> {
    match load(cedar_policy_source) {
        Ok(engine) => {
            let grants = engine.filesystem_grants();
            if let Err(errors) =
                crate::validate_filesystem_paths(&grants.read_only, &grants.read_write)
            {
                violations.extend(errors);
            }
            violations.extend(tls_skip_on_inspected_endpoints(&engine, endpoint_settings));
            engine.warnings().iter().map(ToString::to_string).collect()
        }
        Err(violation) => {
            violations.push(violation);
            Vec::new()
        }
    }
}

/// Rejects `endpoint_settings` entries with `tls: skip` that select an
/// endpoint `HttpRequest` policies inspect: the proxy relays a skipped
/// connection without terminating TLS, so those policies would never run.
fn tls_skip_on_inspected_endpoints(
    engine: &CedarEngine,
    endpoint_settings: &[NetworkEndpoint],
) -> Vec<PolicyViolation> {
    endpoint_settings
        .iter()
        .enumerate()
        .filter(|(_, setting)| setting.tls == NetworkTlsMode::Skip as i32)
        .filter_map(|(index, setting)| {
            let ports = crate::effective_endpoint_ports(setting);
            let (host, port, _, _) =
                engine.configured_l7_endpoints().find(|(host, port, ..)| {
                    ports.contains(&u32::from(*port))
                    // An unparseable host is rejected elsewhere; count it as
                    // overlapping so the check fails closed.
                    && openshell_core::host_pattern::host_patterns_overlap(&setting.host, host)
                        .unwrap_or(true)
                })?;
            Some(PolicyViolation::InvalidEndpointSetting {
                index,
                host: setting.host.clone(),
                reason: format!(
                    "tls: skip relays connections without inspection, but HttpRequest \
                     policies inspect {host}:{port}; remove tls: skip, or narrow its host or \
                     ports so it does not select an inspected endpoint"
                ),
            })
        })
        .collect()
}

/// The Landlock grants a Cedar policy authorizes. A Cedar policy has no
/// `include_workdir`, and needs the supervisor's proxy baseline paths when it
/// can permit `NetworkConnect`.
pub(crate) fn effective_filesystem(
    cedar_policy_source: &str,
) -> std::result::Result<EffectiveFilesystem, PolicyViolation> {
    let engine = load(cedar_policy_source)?;
    let grants = engine.filesystem_grants();
    Ok(EffectiveFilesystem {
        filesystem: Some(FilesystemPolicy {
            include_workdir: false,
            read_only: grants.read_only.clone(),
            read_write: grants.read_write.clone(),
        }),
        needs_proxy_baseline: engine.has_network_permits(),
    })
}

/// Validates the provider credential rules of a Cedar sandbox as a YAML
/// sandbox validates its provider rules.
///
/// Returns `None` when no endpoint carries a token-grant owner, since the
/// rules are compiled only for token-grant owner selection.
///
/// # Errors
///
/// Returns an error when the rules fail policy validation or have ambiguous
/// endpoint selectors.
pub fn provider_token_grant_policy<S: BuildHasher>(
    rules: &HashMap<String, NetworkPolicyRule, S>,
) -> Result<Option<SandboxPolicy>> {
    let stamped = rules
        .values()
        .flat_map(|rule| &rule.endpoints)
        .any(|endpoint| !endpoint.token_grant_owner.is_empty());
    if !stamped {
        return Ok(None);
    }
    let policy = crate::validate_and_canonicalize_sandbox_policy(SandboxPolicy {
        network_policies: rules
            .iter()
            .map(|(name, rule)| (name.clone(), rule.clone()))
            .collect(),
        ..Default::default()
    })
    .map_err(|error| {
        miette::miette!(
            "provider credential rules failed validation ({} violations)",
            error.violations().len()
        )
    })?;
    let ambiguities = crate::find_endpoint_ambiguities(&policy);
    if !ambiguities.is_empty() {
        return Err(miette::miette!(
            "provider credential rules have {} ambiguous endpoint selectors",
            ambiguities.len()
        ));
    }
    Ok(Some(policy))
}

/// Compiles provider rules to Cedar for token-grant owner selection.
///
/// `data` holds the rules of [`provider_token_grant_policy`] normalized as
/// the sandbox's Rego engine reads them: `{"network_policies": {name:
/// {"binaries": [{"path": ...}], "endpoints": [...]}}}`, with protocols,
/// rule aliases, and access presets already expanded.
///
/// # Errors
///
/// Returns an error when the generated Cedar does not load.
pub fn compile_provider_token_grants(data: &Value) -> Result<TokenGrantRules> {
    let mut policies: Vec<ProviderPolicy> = data["network_policies"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, policy)| ProviderPolicy {
            name: name.clone(),
            binaries: strings(&policy["binaries"], |binary| binary["path"].as_str()),
            endpoints: policy["endpoints"]
                .as_array()
                .into_iter()
                .flatten()
                .map(provider_endpoint)
                .collect(),
        })
        .collect();
    policies.sort_by(|left, right| left.name.cmp(&right.name));
    TokenGrantRules::compile(&policies)
        .map_err(|e| miette::miette!("provider credential rules failed to compile: {e}"))
}

/// Collects the strings `get` reads from each element of `array`.
fn strings<'a>(array: &'a Value, get: impl Fn(&'a Value) -> Option<&'a str>) -> Vec<String> {
    array
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(get)
        .map(str::to_string)
        .collect()
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().unwrap_or_default().to_string()
}

/// Reads one normalized endpoint as the Rego rules read it.
fn provider_endpoint(endpoint: &Value) -> ProviderEndpoint {
    ProviderEndpoint {
        host: text(endpoint, "host"),
        ports: endpoint["ports"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .filter_map(|port| u16::try_from(port).ok())
            .collect(),
        path: text(endpoint, "path"),
        has_allowed_ips: endpoint["allowed_ips"]
            .as_array()
            .is_some_and(|ips| !ips.is_empty()),
        protocol: text(endpoint, "protocol"),
        token_grant_owner: text(endpoint, "token_grant_owner"),
        mcp_allow_all_known_methods: endpoint["mcp_allow_all_known_mcp_methods"]
            .as_bool()
            .unwrap_or(false),
        // Rego reads an allow rule's selectors under `allow`.
        rules: endpoint["rules"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|rule| rule.get("allow"))
            .map(rule_matcher)
            .collect(),
        deny_rules: endpoint["deny_rules"]
            .as_array()
            .into_iter()
            .flatten()
            .map(rule_matcher)
            .collect(),
    }
}

fn rule_matcher(rule: &Value) -> RuleMatcher {
    let selector = |key: &str| rule.get(key).and_then(Value::as_str).map(str::to_string);
    RuleMatcher {
        method: selector("method"),
        path: selector("path"),
        command: selector("command"),
        operation_type: selector("operation_type"),
        operation_name: selector("operation_name"),
        fields: strings(&rule["fields"], Value::as_str),
        query: value_matchers(&rule["query"]),
        params: value_matchers(&rule["params"]),
    }
}

/// Reads matchers as `query_value_matches` does: a string is one glob, and
/// an object matches its non-empty `glob` or any of its `any` globs.
fn value_matchers(matchers: &Value) -> BTreeMap<String, ValueMatcher> {
    matchers
        .as_object()
        .into_iter()
        .flatten()
        .map(|(key, matcher)| {
            let mut globs = Vec::new();
            if let Some(glob) = matcher.as_str() {
                globs.push(glob.to_string());
            }
            if let Some(glob) = matcher["glob"].as_str().filter(|glob| !glob.is_empty()) {
                globs.push(glob.to_string());
            }
            globs.extend(strings(&matcher["any"], Value::as_str));
            (key.clone(), ValueMatcher { globs })
        })
        .collect()
}
