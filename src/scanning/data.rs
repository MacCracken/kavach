//! Data and compliance scanner — detect PII, financial data, and
//! regulatory compliance artifacts in sandbox output.
//!
//! Ported from SecureYeoman's `data-scanner.ts`.

use regex::Regex;

use super::types::{ScanFinding, Severity};
use uuid::Uuid;

/// A data pattern with a compiled regex.
struct DataPattern {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: &'static str,
}

const DATA_PATTERNS: &[DataPattern] = &[
    // ── PII ──────────────────────────────────────────────────────────
    DataPattern {
        name: "Credit Card (Visa)",
        category: "pii_financial",
        severity: Severity::Critical,
        regex: r"\b4[0-9]{12}(?:[0-9]{3})?\b",
    },
    DataPattern {
        name: "Credit Card (Mastercard)",
        category: "pii_financial",
        severity: Severity::Critical,
        regex: r"\b5[1-5][0-9]{14}\b",
    },
    DataPattern {
        name: "Credit Card (Amex)",
        category: "pii_financial",
        severity: Severity::Critical,
        regex: r"\b3[47][0-9]{13}\b",
    },
    DataPattern {
        name: "US Phone Number",
        category: "pii",
        severity: Severity::Medium,
        regex: r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
    },
    DataPattern {
        name: "IP Address (IPv4)",
        category: "pii_network",
        severity: Severity::Low,
        regex: r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    },
    DataPattern {
        name: "IBAN",
        category: "pii_financial",
        severity: Severity::High,
        regex: r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,18})?\b",
    },
    // ── Compliance keywords ──────────────────────────────────────────
    DataPattern {
        name: "HIPAA identifier",
        category: "compliance_hipaa",
        severity: Severity::High,
        regex: r"(?i)\b(?:patient\s+(?:id|name|record|dob|ssn|mrn)|medical\s+record\s+number|health\s+insurance\s+claim|protected\s+health\s+information|PHI\b)",
    },
    DataPattern {
        name: "GDPR personal data",
        category: "compliance_gdpr",
        severity: Severity::Medium,
        regex: r"(?i)\b(?:data\s+subject|right\s+to\s+erasure|right\s+to\s+be\s+forgotten|consent\s+withdraw|data\s+processing\s+agreement|data\s+controller|data\s+processor)\b",
    },
    DataPattern {
        name: "PCI-DSS cardholder data",
        category: "compliance_pci",
        severity: Severity::High,
        regex: r"(?i)\b(?:cardholder\s+data|card\s+verification|CVV|CVC|primary\s+account\s+number|PAN\s+data|track\s+data|magnetic\s+stripe)\b",
    },
    DataPattern {
        name: "SOC2 audit artifact",
        category: "compliance_soc2",
        severity: Severity::Medium,
        regex: r"(?i)\b(?:SOC\s*2|trust\s+service\s+criteria|system\s+description|complementary\s+user\s+entity\s+controls|CUEC)\b",
    },
];

/// Compiled data patterns — compiled once, shared across all instances.
static COMPILED_DATA_PATTERNS: std::sync::LazyLock<Vec<CompiledDataPattern>> =
    std::sync::LazyLock::new(|| {
        DATA_PATTERNS
            .iter()
            .filter_map(|p| {
                Regex::new(p.regex).ok().map(|regex| CompiledDataPattern {
                    name: p.name,
                    category: p.category,
                    severity: p.severity,
                    regex,
                })
            })
            .collect()
    });

struct CompiledDataPattern {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    regex: Regex,
}

/// Data and compliance scanner.
///
/// Detects PII (credit cards, phone numbers, IPs, IBANs), and regulatory
/// compliance artifacts (HIPAA, GDPR, PCI-DSS, SOC2) in sandbox output.
#[derive(Debug)]
pub struct DataScanner;

impl DataScanner {
    /// Create a new data scanner (cheap — patterns compiled once globally).
    #[must_use]
    pub fn new() -> Self {
        let _ = &*COMPILED_DATA_PATTERNS;
        Self
    }

    /// Scan text for PII and compliance data. Returns findings.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<ScanFinding> {
        let mut findings = Vec::new();
        for pattern in &*COMPILED_DATA_PATTERNS {
            if let Some(m) = pattern.regex.find(text) {
                let evidence = m.as_str();
                let truncated = if evidence.len() > 20 {
                    let mut end = 20;
                    while end > 0 && !evidence.is_char_boundary(end) {
                        end -= 1;
                    }
                    format!("{}...", &evidence[..end])
                } else {
                    evidence.to_string()
                };
                findings.push(ScanFinding {
                    id: Uuid::new_v4(),
                    scanner: "data".into(),
                    severity: pattern.severity,
                    category: pattern.category.into(),
                    message: format!("{} detected", pattern.name),
                    evidence: Some(truncated),
                });
            }
        }
        findings
    }
}

impl Default for DataScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> DataScanner {
        DataScanner::new()
    }

    // ── Credit cards ─────────────────────────────────────────────────

    #[test]
    fn detect_visa() {
        let findings = scanner().scan("card: 4111111111111111");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "pii_financial"));
    }

    #[test]
    fn detect_mastercard() {
        let findings = scanner().scan("card: 5500000000000004");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detect_amex() {
        let findings = scanner().scan("card: 378282246310005");
        assert!(!findings.is_empty());
    }

    // ── Phone numbers ────────────────────────────────────────────────

    #[test]
    fn detect_us_phone() {
        let findings = scanner().scan("call me at (555) 123-4567");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "pii"));
    }

    // ── IP addresses ─────────────────────────────────────────────────

    #[test]
    fn detect_ipv4() {
        let findings = scanner().scan("server at 192.168.1.100");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "pii_network"));
    }

    #[test]
    fn no_false_positive_version() {
        // Version numbers like 1.2.3 should not match (no 4th octet)
        let findings = scanner().scan("version 1.2.3");
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "pii_network")
            .collect();
        assert!(ip_findings.is_empty());
    }

    // ── IBAN ─────────────────────────────────────────────────────────

    #[test]
    fn detect_iban() {
        let findings = scanner().scan("IBAN: DE89370400440532013000");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "pii_financial"));
    }

    // ── Compliance ───────────────────────────────────────────────────

    #[test]
    fn detect_hipaa() {
        let findings = scanner().scan("patient record number: MRN-12345");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "compliance_hipaa"));
    }

    #[test]
    fn detect_gdpr() {
        let findings = scanner().scan("data subject right to erasure request");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "compliance_gdpr"));
    }

    #[test]
    fn detect_pci() {
        let findings = scanner().scan("cardholder data environment");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "compliance_pci"));
    }

    #[test]
    fn detect_soc2() {
        let findings = scanner().scan("SOC 2 trust service criteria audit");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "compliance_soc2"));
    }

    // ── Clean output ─────────────────────────────────────────────────

    #[test]
    fn clean_output_no_findings() {
        let findings = scanner().scan("hello world\nstatus: ok\nresult: 42\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn empty_input() {
        assert!(scanner().scan("").is_empty());
    }
}
