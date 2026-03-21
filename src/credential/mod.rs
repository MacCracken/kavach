//! Credential proxy — inject secrets into sandboxes without exposing them.

use serde::{Deserialize, Serialize};

/// Reference to a secret (name only — the actual value is never in the sandbox config).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRef {
    /// Secret name (e.g. "OPENAI_API_KEY", "DATABASE_URL").
    pub name: String,
    /// Injection method.
    pub inject_via: InjectionMethod,
}

/// How a secret is delivered to the sandboxed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InjectionMethod {
    /// Set as an environment variable.
    EnvVar { var_name: String },
    /// Write to a file inside the sandbox.
    File { path: String, mode: u32 },
    /// Pipe through stdin.
    Stdin,
}

/// Descriptor for a file-based secret injection.
#[derive(Debug, Clone)]
pub struct FileInjection {
    /// Path inside the sandbox to write the secret to.
    pub path: String,
    /// Secret content.
    pub content: String,
    /// File permissions (e.g. 0o600).
    pub mode: u32,
}

/// The credential proxy manages secret lifecycle for sandboxed execution.
pub struct CredentialProxy {
    secrets: std::collections::HashMap<String, String>,
}

impl CredentialProxy {
    pub fn new() -> Self {
        Self {
            secrets: std::collections::HashMap::new(),
        }
    }

    /// Register a secret (stored in memory, never written to disk).
    pub fn register(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.secrets.insert(name.into(), value.into());
    }

    /// Resolve a secret reference to its value.
    pub fn resolve(&self, secret_ref: &SecretRef) -> Option<&str> {
        self.secrets.get(&secret_ref.name).map(|s| s.as_str())
    }

    /// Build environment variables for a set of secret refs.
    /// Only returns refs with `InjectionMethod::EnvVar`.
    pub fn env_vars(&self, refs: &[SecretRef]) -> Vec<(String, String)> {
        refs.iter()
            .filter_map(|r| {
                let value = self.resolve(r)?;
                match &r.inject_via {
                    InjectionMethod::EnvVar { var_name } => {
                        Some((var_name.clone(), value.to_string()))
                    }
                    _ => None,
                }
            })
            .collect()
    }

    /// Build file injection descriptors for a set of secret refs.
    /// Returns (path, content, mode) tuples for refs with `InjectionMethod::File`.
    /// The caller is responsible for writing these files inside the sandbox.
    pub fn file_injections(&self, refs: &[SecretRef]) -> Vec<FileInjection> {
        refs.iter()
            .filter_map(|r| {
                let value = self.resolve(r)?;
                match &r.inject_via {
                    InjectionMethod::File { path, mode } => Some(FileInjection {
                        path: path.clone(),
                        content: value.to_string(),
                        mode: *mode,
                    }),
                    _ => None,
                }
            })
            .collect()
    }

    /// Build a stdin payload from all refs with `InjectionMethod::Stdin`.
    /// Secrets are concatenated with newline separators.
    /// Returns None if no stdin-injected secrets exist.
    pub fn stdin_payload(&self, refs: &[SecretRef]) -> Option<String> {
        let parts: Vec<&str> = refs
            .iter()
            .filter_map(|r| {
                if matches!(r.inject_via, InjectionMethod::Stdin) {
                    self.resolve(r)
                } else {
                    None
                }
            })
            .collect();

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("\n"))
        }
    }

    /// Number of registered secrets.
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

impl Default for CredentialProxy {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_resolve() {
        let mut proxy = CredentialProxy::new();
        proxy.register("API_KEY", "sk-12345");
        let r = SecretRef {
            name: "API_KEY".into(),
            inject_via: InjectionMethod::EnvVar {
                var_name: "OPENAI_API_KEY".into(),
            },
        };
        assert_eq!(proxy.resolve(&r), Some("sk-12345"));
    }

    #[test]
    fn resolve_missing() {
        let proxy = CredentialProxy::new();
        let r = SecretRef {
            name: "NOPE".into(),
            inject_via: InjectionMethod::Stdin,
        };
        assert!(proxy.resolve(&r).is_none());
    }

    #[test]
    fn env_vars_generation() {
        let mut proxy = CredentialProxy::new();
        proxy.register("KEY1", "val1");
        proxy.register("KEY2", "val2");
        let refs = vec![
            SecretRef {
                name: "KEY1".into(),
                inject_via: InjectionMethod::EnvVar {
                    var_name: "MY_KEY_1".into(),
                },
            },
            SecretRef {
                name: "KEY2".into(),
                inject_via: InjectionMethod::File {
                    path: "/tmp/secret".into(),
                    mode: 0o600,
                },
            },
        ];
        let vars = proxy.env_vars(&refs);
        assert_eq!(vars.len(), 1); // Only EnvVar injection
        assert_eq!(vars[0], ("MY_KEY_1".into(), "val1".into()));
    }

    #[test]
    fn empty_proxy() {
        let proxy = CredentialProxy::new();
        assert!(proxy.is_empty());
        assert_eq!(proxy.len(), 0);
    }

    #[test]
    fn file_injections() {
        let mut proxy = CredentialProxy::new();
        proxy.register("DB_CERT", "-----BEGIN CERTIFICATE-----\nMII...");
        proxy.register("API_KEY", "sk-12345");

        let refs = vec![
            SecretRef {
                name: "DB_CERT".into(),
                inject_via: InjectionMethod::File {
                    path: "/etc/ssl/db.pem".into(),
                    mode: 0o600,
                },
            },
            SecretRef {
                name: "API_KEY".into(),
                inject_via: InjectionMethod::EnvVar {
                    var_name: "KEY".into(),
                },
            },
        ];

        let files = proxy.file_injections(&refs);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "/etc/ssl/db.pem");
        assert!(files[0].content.contains("CERTIFICATE"));
        assert_eq!(files[0].mode, 0o600);
    }

    #[test]
    fn file_injection_missing_secret() {
        let proxy = CredentialProxy::new();
        let refs = vec![SecretRef {
            name: "MISSING".into(),
            inject_via: InjectionMethod::File {
                path: "/tmp/secret".into(),
                mode: 0o400,
            },
        }];
        assert!(proxy.file_injections(&refs).is_empty());
    }

    #[test]
    fn stdin_payload() {
        let mut proxy = CredentialProxy::new();
        proxy.register("TOKEN_A", "secret-a");
        proxy.register("TOKEN_B", "secret-b");

        let refs = vec![
            SecretRef {
                name: "TOKEN_A".into(),
                inject_via: InjectionMethod::Stdin,
            },
            SecretRef {
                name: "TOKEN_B".into(),
                inject_via: InjectionMethod::Stdin,
            },
        ];

        let payload = proxy.stdin_payload(&refs).unwrap();
        assert_eq!(payload, "secret-a\nsecret-b");
    }

    #[test]
    fn stdin_payload_none_when_empty() {
        let proxy = CredentialProxy::new();
        let refs = vec![SecretRef {
            name: "KEY".into(),
            inject_via: InjectionMethod::EnvVar {
                var_name: "X".into(),
            },
        }];
        assert!(proxy.stdin_payload(&refs).is_none());
    }

    #[test]
    fn stdin_payload_missing_secret() {
        let proxy = CredentialProxy::new();
        let refs = vec![SecretRef {
            name: "MISSING".into(),
            inject_via: InjectionMethod::Stdin,
        }];
        assert!(proxy.stdin_payload(&refs).is_none());
    }

    #[test]
    fn mixed_injection_methods() {
        let mut proxy = CredentialProxy::new();
        proxy.register("ENV_SECRET", "env-val");
        proxy.register("FILE_SECRET", "file-val");
        proxy.register("STDIN_SECRET", "stdin-val");

        let refs = vec![
            SecretRef {
                name: "ENV_SECRET".into(),
                inject_via: InjectionMethod::EnvVar {
                    var_name: "MY_ENV".into(),
                },
            },
            SecretRef {
                name: "FILE_SECRET".into(),
                inject_via: InjectionMethod::File {
                    path: "/run/secrets/key".into(),
                    mode: 0o400,
                },
            },
            SecretRef {
                name: "STDIN_SECRET".into(),
                inject_via: InjectionMethod::Stdin,
            },
        ];

        assert_eq!(proxy.env_vars(&refs).len(), 1);
        assert_eq!(proxy.file_injections(&refs).len(), 1);
        assert!(proxy.stdin_payload(&refs).is_some());
    }
}
