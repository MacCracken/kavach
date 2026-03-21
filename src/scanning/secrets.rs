//! Secrets scanner — detect credentials and sensitive data in output.
//!
//! Patterns ported from SecureYeoman's `secrets-scanner.ts`.

use regex::Regex;

use super::types::{ScanFinding, Severity};
use uuid::Uuid;

/// A secret detection pattern.
struct SecretPattern {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: &'static str,
}

const PATTERNS: &[SecretPattern] = &[
    SecretPattern {
        name: "AWS Access Key",
        category: "cloud_credential",
        severity: Severity::Critical,
        regex: r"AKIA[0-9A-Z]{16}",
    },
    SecretPattern {
        name: "AWS Secret Key",
        category: "cloud_credential",
        severity: Severity::Critical,
        regex: r#"(?i)aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]"#,
    },
    SecretPattern {
        name: "GCP API Key",
        category: "cloud_credential",
        severity: Severity::High,
        regex: r"AIza[0-9A-Za-z\-_]{35}",
    },
    SecretPattern {
        name: "GitHub Token",
        category: "api_token",
        severity: Severity::Critical,
        regex: r"gh[ps]_[A-Za-z0-9_]{36,}",
    },
    SecretPattern {
        name: "Stripe Secret Key",
        category: "api_token",
        severity: Severity::Critical,
        regex: r"sk_(live|test)_[0-9a-zA-Z]{24,}",
    },
    SecretPattern {
        name: "Slack Token",
        category: "api_token",
        severity: Severity::High,
        regex: r"xox[bpas]-[0-9a-zA-Z\-]{10,}",
    },
    SecretPattern {
        name: "Generic API Key",
        category: "api_key",
        severity: Severity::Medium,
        regex: r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]"#,
    },
    SecretPattern {
        name: "Bearer Token",
        category: "auth_token",
        severity: Severity::High,
        regex: r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}",
    },
    SecretPattern {
        name: "JWT",
        category: "auth_token",
        severity: Severity::High,
        regex: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    },
    SecretPattern {
        name: "RSA Private Key",
        category: "private_key",
        severity: Severity::Critical,
        regex: r"-----BEGIN RSA PRIVATE KEY-----",
    },
    SecretPattern {
        name: "EC Private Key",
        category: "private_key",
        severity: Severity::Critical,
        regex: r"-----BEGIN EC PRIVATE KEY-----",
    },
    SecretPattern {
        name: "OpenSSH Private Key",
        category: "private_key",
        severity: Severity::Critical,
        regex: r"-----BEGIN OPENSSH PRIVATE KEY-----",
    },
    SecretPattern {
        name: "Generic Private Key",
        category: "private_key",
        severity: Severity::Critical,
        regex: r"-----BEGIN PRIVATE KEY-----",
    },
    SecretPattern {
        name: "Password Assignment",
        category: "credential",
        severity: Severity::High,
        regex: r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]"#,
    },
    SecretPattern {
        name: "Database Connection String",
        category: "connection_string",
        severity: Severity::Critical,
        regex: r"(?i)(postgres|mysql|mongodb|redis)://[^\s]{10,}",
    },
    SecretPattern {
        name: "Email Address",
        category: "pii",
        severity: Severity::Low,
        regex: r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    },
    SecretPattern {
        name: "SSN",
        category: "pii",
        severity: Severity::Critical,
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
    },
];

/// Compiled scanner with pre-built regex patterns.
pub struct SecretsScanner {
    compiled: Vec<CompiledPattern>,
}

struct CompiledPattern {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: Regex,
}

impl SecretsScanner {
    /// Create a new scanner with compiled patterns.
    pub fn new() -> Self {
        let compiled = PATTERNS
            .iter()
            .filter_map(|p| {
                Regex::new(p.regex).ok().map(|regex| CompiledPattern {
                    name: p.name,
                    category: p.category,
                    severity: p.severity,
                    regex,
                })
            })
            .collect();
        Self { compiled }
    }

    /// Scan text for secrets. Returns findings.
    pub fn scan(&self, text: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for pattern in &self.compiled {
            if let Some(m) = pattern.regex.find(text) {
                let evidence = m.as_str();
                // Truncate evidence to avoid leaking the full secret
                let truncated = if evidence.len() > 20 {
                    format!("{}...", &evidence[..20])
                } else {
                    evidence.to_string()
                };
                findings.push(ScanFinding {
                    id: Uuid::new_v4(),
                    scanner: "secrets".into(),
                    severity: pattern.severity,
                    category: pattern.category.into(),
                    message: format!("{} detected", pattern.name),
                    evidence: Some(truncated),
                });
            }
        }
        findings
    }

    /// Redact secrets in text, replacing matches with `[REDACTED:CATEGORY]`.
    pub fn redact(&self, text: &str) -> String {
        let mut result = text.to_string();
        for pattern in &self.compiled {
            result = pattern
                .regex
                .replace_all(&result, format!("[REDACTED:{}]", pattern.category))
                .into_owned();
        }
        result
    }
}

impl Default for SecretsScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_aws_key() {
        let scanner = SecretsScanner::new();
        let findings = scanner.scan("my key is AKIAIOSFODNN7EXAMPLE");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].category, "cloud_credential");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detect_github_token() {
        let scanner = SecretsScanner::new();
        let findings = scanner.scan("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("GitHub")));
    }

    #[test]
    fn detect_private_key() {
        let scanner = SecretsScanner::new();
        let findings = scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn detect_jwt() {
        let scanner = SecretsScanner::new();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop";
        let findings = scanner.scan(jwt);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.message.contains("JWT")));
    }

    #[test]
    fn detect_connection_string() {
        let scanner = SecretsScanner::new();
        let findings = scanner.scan("DATABASE_URL=postgres://user:pass@localhost/db");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "connection_string"));
    }

    #[test]
    fn clean_text_no_findings() {
        let scanner = SecretsScanner::new();
        let findings = scanner.scan("hello world, this is clean output");
        assert!(findings.is_empty());
    }

    #[test]
    fn redact_replaces_secrets() {
        let scanner = SecretsScanner::new();
        let input = "key: AKIAIOSFODNN7EXAMPLE rest";
        let redacted = scanner.redact(input);
        assert!(redacted.contains("[REDACTED:cloud_credential]"));
        assert!(!redacted.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redact_preserves_clean_text() {
        let scanner = SecretsScanner::new();
        let input = "hello world";
        assert_eq!(scanner.redact(input), "hello world");
    }
}
