// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provider rules of a Cedar sandbox, compiled to Cedar for token grants.
//!
//! The gateway delivers attached providers' rules to a Cedar sandbox in
//! `provider_credential_rules`, with each endpoint stamped with the owner of
//! its token grants. `openshell_policy::cedar` validates them and compiles
//! them to Cedar; this module supplies the sandbox-specific preparation in
//! between: symlinked binaries resolved in the sandbox, and the protocol
//! spellings, L7 checks, MCP tool aliases, and access presets the YAML engine
//! applies when it loads the same rules. No Rego is involved.

use std::collections::HashMap;

use miette::Result;
use openshell_core::proto::{NetworkPolicyRule, SandboxPolicy as ProtoSandboxPolicy};
use openshell_ocsf::{ConfigStateChangeBuilder, SeverityId, StateId, StatusId, ocsf_emit};
use openshell_policy_cedar::TokenGrantRules;
use serde_json::Value;

use crate::policy_data::{
    endpoint_policy_value, normalize_endpoint_protocols, normalize_l7_policy_rule_aliases,
};

/// Compiles provider rules for token-grant owner selection.
///
/// Returns `None` when no provider endpoint carries an owner. Binary paths
/// are resolved in the root filesystem of `entrypoint_pid` (none when it is
/// 0), as a YAML sandbox resolves them.
///
/// # Errors
///
/// Returns an error when the rules fail the validation a YAML sandbox
/// applies to them, or the generated Cedar does not load.
pub fn compile(
    rules: &HashMap<String, NetworkPolicyRule>,
    entrypoint_pid: u32,
) -> Result<Option<TokenGrantRules>> {
    let Some(policy) = openshell_policy::cedar::provider_token_grant_policy(rules)? else {
        return Ok(None);
    };
    let data = normalized_rules(&policy, entrypoint_pid)?;
    let compiled = openshell_policy::cedar::compile_provider_token_grants(&data)?;
    report(&compiled);
    Ok(Some(compiled))
}

/// Normalizes validated provider rules as the YAML engine loads them.
fn normalized_rules(policy: &ProtoSandboxPolicy, entrypoint_pid: u32) -> Result<Value> {
    let network_policies: serde_json::Map<String, Value> = policy
        .network_policies
        .iter()
        .map(|(key, rule)| {
            let binaries: Vec<Value> = rule
                .binaries
                .iter()
                .flat_map(|binary| {
                    let resolved = crate::binary_resolution::resolve_policy_binary(
                        &binary.path,
                        entrypoint_pid,
                    );
                    std::iter::once(binary.path.clone()).chain(resolved)
                })
                .map(|path| serde_json::json!({ "path": path }))
                .collect();
            let endpoints: Vec<Value> = rule
                .endpoints
                .iter()
                .map(|endpoint| endpoint_policy_value(endpoint, ""))
                .collect();
            (
                key.clone(),
                serde_json::json!({ "endpoints": endpoints, "binaries": binaries }),
            )
        })
        .collect();
    let mut data = serde_json::json!({ "network_policies": network_policies });
    normalize_endpoint_protocols(&mut data);
    let (errors, _) = crate::l7::validate_l7_policies(&data);
    if !errors.is_empty() {
        return Err(miette::miette!(
            "provider credential rules have {} invalid L7 configurations",
            errors.len()
        ));
    }
    normalize_l7_policy_rule_aliases(&mut data);
    let _ = crate::l7::expand_access_presets(&mut data);
    Ok(data)
}

/// Reports provider selectors compiled other than exactly.
fn report(compiled: &TokenGrantRules) {
    if compiled.untranslated().is_empty() {
        return;
    }
    let notes: Vec<String> = compiled
        .untranslated()
        .iter()
        .map(ToString::to_string)
        .collect();
    let (severity, summary) = if compiled.fail_closed_reason().is_some() {
        (
            SeverityId::Medium,
            "no token grant is admitted for any request",
        )
    } else {
        (
            SeverityId::Low,
            "some token grants are admitted for fewer requests",
        )
    };
    tracing::warn!(rules = ?notes, "provider rules not translated exactly to Cedar; {summary}");
    ocsf_emit!(
        ConfigStateChangeBuilder::new(openshell_ocsf::ctx::ctx())
            .severity(severity)
            .status(StatusId::Success)
            .state(StateId::Enabled, "provider token grants compiled")
            .unmapped("untranslated_provider_rules", serde_json::json!(notes))
            .message(format!(
                "CONFIG:TOKEN_GRANTS provider rules not translated exactly to Cedar [count:{}]; {summary}",
                notes.len()
            ))
            .build()
    );
}
