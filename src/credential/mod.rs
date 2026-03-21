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
}
