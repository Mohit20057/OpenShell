// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use openshell_core::sandbox_env::{
    OTEL_EXPORTER_OTLP_COMPRESSION, OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_PROTOCOL,
    OTEL_EXPORTER_OTLP_TRACES_COMPRESSION, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
    OTEL_EXPORTER_OTLP_TRACES_PROTOCOL, OTLP_RELAY_ENDPOINT, OTLP_RELAY_TRACES_ENDPOINT,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsEnvironmentMode {
    /// `OpenShell`'s generated trust files are authoritative for mediated traffic.
    Override,
    /// Preserve caller-provided TLS variables and fill only missing values.
    FillMissing,
}

const TLS_ENVIRONMENT_VARIABLES: [&str; 6] = [
    "NODE_EXTRA_CA_CERTS",
    "DENO_CERT",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "GIT_SSL_CAINFO",
];

#[must_use]
pub fn is_tls_environment_variable(key: &str) -> bool {
    TLS_ENVIRONMENT_VARIABLES.contains(&key)
}

pub fn tls_env_vars_for_mode<S: std::hash::BuildHasher>(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
    mode: TlsEnvironmentMode,
    user_environment: &std::collections::HashMap<String, String, S>,
) -> Vec<(&'static str, String)> {
    tls_env_vars(ca_cert_path, combined_bundle_path)
        .into_iter()
        .filter(|(key, _)| {
            matches!(mode, TlsEnvironmentMode::Override) || !user_environment.contains_key(*key)
        })
        .collect()
}

/// OpenTelemetry exporter variables every workload process receives.
///
/// They point agent SDKs at the supervisor's OTLP relay and are applied after
/// the environment from the sandbox creation request, so an endpoint named
/// there never wins: it would either point into the fenced network and fail
/// or bypass attribution. The signal-specific traces variables are set as
/// well because SDKs give them precedence over the generic ones, and
/// compression is disabled because the relay refuses compressed bodies. The
/// values are the same whether or not a collector is configured; without one
/// the relay address refuses connections immediately. A per-exec environment
/// still overrides them for that exec only.
pub fn otlp_relay_env_vars() -> [(&'static str, &'static str); 6] {
    [
        (OTEL_EXPORTER_OTLP_ENDPOINT, OTLP_RELAY_ENDPOINT),
        (OTEL_EXPORTER_OTLP_PROTOCOL, "http/protobuf"),
        (
            OTEL_EXPORTER_OTLP_TRACES_ENDPOINT,
            OTLP_RELAY_TRACES_ENDPOINT,
        ),
        (OTEL_EXPORTER_OTLP_TRACES_PROTOCOL, "http/protobuf"),
        (OTEL_EXPORTER_OTLP_COMPRESSION, "none"),
        (OTEL_EXPORTER_OTLP_TRACES_COMPRESSION, "none"),
    ]
}

pub fn tls_env_vars(
    ca_cert_path: &Path,
    combined_bundle_path: &Path,
) -> [(&'static str, String); 6] {
    let ca_cert_path = ca_cert_path.display().to_string();
    let combined_bundle_path = combined_bundle_path.display().to_string();
    [
        ("NODE_EXTRA_CA_CERTS", ca_cert_path.clone()),
        ("DENO_CERT", ca_cert_path),
        ("SSL_CERT_FILE", combined_bundle_path.clone()),
        ("REQUESTS_CA_BUNDLE", combined_bundle_path.clone()),
        ("CURL_CA_BUNDLE", combined_bundle_path.clone()),
        // Ubuntu Noble's git links against libcurl-gnutls, which ignores SSL_CERT_FILE.
        // git reads GIT_SSL_CAINFO (or http.sslCAInfo) to locate the CA bundle.
        ("GIT_SSL_CAINFO", combined_bundle_path),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::process::Stdio;

    #[test]
    fn apply_tls_env_sets_node_and_bundle_paths() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let ca_cert_path = Path::new("/etc/openshell-tls/openshell-ca.pem");
        let combined_bundle_path = Path::new("/etc/openshell-tls/ca-bundle.pem");
        for (key, value) in tls_env_vars(ca_cert_path, combined_bundle_path) {
            cmd.env(key, value);
        }

        let output = cmd.output().expect("spawn env");
        let stdout = String::from_utf8(output.stdout).expect("utf8");

        assert!(stdout.contains("NODE_EXTRA_CA_CERTS=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("DENO_CERT=/etc/openshell-tls/openshell-ca.pem"));
        assert!(stdout.contains("SSL_CERT_FILE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("REQUESTS_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("CURL_CA_BUNDLE=/etc/openshell-tls/ca-bundle.pem"));
        assert!(stdout.contains("GIT_SSL_CAINFO=/etc/openshell-tls/ca-bundle.pem"));

        let keys = tls_env_vars(ca_cert_path, combined_bundle_path).map(|(key, _)| key);
        assert!(
            !keys.contains(&openshell_core::sandbox_env::TLS_CA),
            "destination/child trust must not overwrite gateway mTLS trust"
        );
        assert_ne!(
            ca_cert_path,
            Path::new(openshell_core::container_paths::TLS_CA_MOUNT_PATH)
        );
    }

    #[test]
    fn otlp_relay_env_points_sdks_at_the_reserved_endpoint() {
        assert_eq!(
            otlp_relay_env_vars(),
            [
                ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://192.0.0.8:4318"),
                ("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"),
                (
                    "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
                    "http://192.0.0.8:4318/v1/traces"
                ),
                ("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf"),
                ("OTEL_EXPORTER_OTLP_COMPRESSION", "none"),
                ("OTEL_EXPORTER_OTLP_TRACES_COMPRESSION", "none"),
            ]
        );
    }
}
