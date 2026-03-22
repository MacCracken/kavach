//! Externalization gate — scans sandbox output before releasing to caller.

use super::secrets::SecretsScanner;
use super::types::{ExternalizationPolicy, ScanResult, ScanVerdict, Severity};
use crate::lifecycle::ExecResult;

/// The externalization gate wraps sandbox results and applies content policy.
pub struct ExternalizationGate {
    scanner: SecretsScanner,
}

impl ExternalizationGate {
    pub fn new() -> Self {
        Self {
            scanner: SecretsScanner::new(),
        }
    }

    /// Apply the externalization gate to an exec result.
    /// May redact content, block the result, or pass it through.
    pub fn apply(
        &self,
        mut result: ExecResult,
        policy: &ExternalizationPolicy,
    ) -> crate::Result<ExecResult> {
        if !policy.enabled {
            return Ok(result);
        }

        // Check size limits
        let total_size = result.stdout.len() + result.stderr.len();
        if total_size > policy.max_artifact_size_bytes {
            return Err(crate::KavachError::ExternalizationBlocked(format!(
                "output size {} exceeds limit {}",
                total_size, policy.max_artifact_size_bytes
            )));
        }

        // Scan stdout and stderr
        let mut stdout_findings = self.scanner.scan(&result.stdout);
        let mut stderr_findings = self.scanner.scan(&result.stderr);
        stdout_findings.append(&mut stderr_findings);

        let worst_severity = stdout_findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Info);

        let scan_result = ScanResult {
            verdict: determine_verdict(worst_severity, policy),
            findings: stdout_findings,
            worst_severity,
        };

        match scan_result.verdict {
            ScanVerdict::Block => Err(crate::KavachError::ExternalizationBlocked(format!(
                "blocked: {} finding(s), worst severity: {}",
                scan_result.findings.len(),
                scan_result.worst_severity
            ))),
            ScanVerdict::Quarantine => Err(crate::KavachError::ExternalizationBlocked(format!(
                "quarantined: {} finding(s), worst severity: {}",
                scan_result.findings.len(),
                scan_result.worst_severity
            ))),
            ScanVerdict::Warn => {
                if policy.redact_secrets {
                    result.stdout = self.scanner.redact(&result.stdout);
                    result.stderr = self.scanner.redact(&result.stderr);
                }
                Ok(result)
            }
            ScanVerdict::Pass => Ok(result),
        }
    }
}

impl Default for ExternalizationGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine verdict based on worst severity and policy thresholds.
fn determine_verdict(worst: Severity, policy: &ExternalizationPolicy) -> ScanVerdict {
    if worst >= policy.block_threshold {
        ScanVerdict::Block
    } else if worst >= policy.quarantine_threshold {
        ScanVerdict::Quarantine
    } else if worst > Severity::Info {
        ScanVerdict::Warn
    } else {
        ScanVerdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(stdout: &str) -> ExecResult {
        ExecResult {
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
            duration_ms: 0,
            timed_out: false,
        }
    }

    #[test]
    fn pass_clean_output() {
        let gate = ExternalizationGate::new();
        let policy = ExternalizationPolicy::default();
        let result = gate.apply(make_result("hello world"), &policy).unwrap();
        assert_eq!(result.stdout, "hello world");
    }

    #[test]
    fn block_private_key() {
        let gate = ExternalizationGate::new();
        let policy = ExternalizationPolicy::default();
        let result = gate.apply(
            make_result("-----BEGIN RSA PRIVATE KEY-----\nMIIEp..."),
            &policy,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn redact_medium_severity() {
        let gate = ExternalizationGate::new();
        let policy = ExternalizationPolicy {
            quarantine_threshold: Severity::High,
            block_threshold: Severity::Critical,
            ..Default::default()
        };
        let result = gate
            .apply(
                make_result(r#"config: api_key = "abcdefghijklmnopqrstuvwxyz""#),
                &policy,
            )
            .unwrap();
        assert!(result.stdout.contains("[REDACTED:"));
    }

    #[test]
    fn block_oversized() {
        let gate = ExternalizationGate::new();
        let policy = ExternalizationPolicy {
            max_artifact_size_bytes: 10,
            ..Default::default()
        };
        let result = gate.apply(make_result("this is longer than 10 bytes"), &policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("size"));
    }

    #[test]
    fn disabled_gate_passes_everything() {
        let gate = ExternalizationGate::new();
        let policy = ExternalizationPolicy {
            enabled: false,
            ..Default::default()
        };
        let result = gate
            .apply(make_result("-----BEGIN RSA PRIVATE KEY-----"), &policy)
            .unwrap();
        assert!(result.stdout.contains("BEGIN RSA PRIVATE KEY"));
    }

    #[test]
    fn verdict_determination() {
        let policy = ExternalizationPolicy::default();
        assert_eq!(
            determine_verdict(Severity::Info, &policy),
            ScanVerdict::Pass
        );
        assert_eq!(determine_verdict(Severity::Low, &policy), ScanVerdict::Warn);
        assert_eq!(
            determine_verdict(Severity::High, &policy),
            ScanVerdict::Quarantine
        );
        assert_eq!(
            determine_verdict(Severity::Critical, &policy),
            ScanVerdict::Block
        );
    }
}
