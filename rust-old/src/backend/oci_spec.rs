//! Shared OCI runtime spec generation from SandboxConfig.
//!
//! Used by both gVisor (runsc) and OCI (runc/crun) backends.

#[cfg(any(feature = "gvisor", feature = "oci"))]
pub use ::oci_spec::runtime as oci_runtime;

use crate::lifecycle::SandboxConfig;

/// Generate an OCI runtime spec from a SandboxConfig.
#[cfg(any(feature = "gvisor", feature = "oci"))]
pub fn generate_spec(config: &SandboxConfig) -> crate::Result<oci_runtime::Spec> {
    use oci_runtime::*;

    let policy = &config.policy;

    // Root filesystem
    let root = RootBuilder::default()
        .path("rootfs")
        .readonly(policy.read_only_rootfs)
        .build()
        .map_err(|e| crate::KavachError::CreationFailed(format!("OCI root: {e}")))?;

    // Environment variables
    let mut env: Vec<String> = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
    ];
    for (k, v) in &config.env {
        env.push(format!("{k}={v}"));
    }

    let cwd = config.workdir.clone().unwrap_or_else(|| "/".to_string());

    // Process — builders consume self, so chain
    let process = ProcessBuilder::default()
        .terminal(false)
        .args(vec!["/bin/sh".into(), "-c".into(), "echo ready".into()])
        .cwd(cwd)
        .env(env)
        .build()
        .map_err(|e| crate::KavachError::CreationFailed(format!("OCI process: {e}")))?;

    // Linux-specific: resource limits
    let linux = {
        let mut builder = LinuxBuilder::default();

        let has_memory = policy.memory_limit_mb.is_some();
        let has_pids = policy.max_pids.is_some();

        if has_memory || has_pids {
            let mut res_builder = LinuxResourcesBuilder::default();

            if let Some(mb) = policy.memory_limit_mb {
                let bytes = (mb * 1024 * 1024) as i64;
                let memory = LinuxMemoryBuilder::default()
                    .limit(bytes)
                    .build()
                    .map_err(|e| crate::KavachError::CreationFailed(format!("OCI memory: {e}")))?;
                res_builder = res_builder.memory(memory);
            }

            if let Some(pids) = policy.max_pids {
                let pids_limit = LinuxPidsBuilder::default()
                    .limit(pids as i64)
                    .build()
                    .map_err(|e| crate::KavachError::CreationFailed(format!("OCI pids: {e}")))?;
                res_builder = res_builder.pids(pids_limit);
            }

            let resources = res_builder
                .build()
                .map_err(|e| crate::KavachError::CreationFailed(format!("OCI resources: {e}")))?;
            builder = builder.resources(resources);
        }

        builder
            .build()
            .map_err(|e| crate::KavachError::CreationFailed(format!("OCI linux: {e}")))?
    };

    // Build the spec
    let spec = SpecBuilder::default()
        .version("1.0.2")
        .root(root)
        .process(process)
        .linux(linux)
        .build()
        .map_err(|e| crate::KavachError::CreationFailed(format!("OCI spec: {e}")))?;

    Ok(spec)
}

/// Write the OCI spec to a config.json file in the bundle directory.
#[cfg(any(feature = "gvisor", feature = "oci"))]
pub fn write_spec(spec: &oci_runtime::Spec, bundle_dir: &std::path::Path) -> crate::Result<()> {
    let config_path = bundle_dir.join("config.json");
    let json = serde_json::to_string_pretty(spec)
        .map_err(|e| crate::KavachError::CreationFailed(format!("OCI spec serialize: {e}")))?;
    std::fs::write(&config_path, json)
        .map_err(|e| crate::KavachError::CreationFailed(format!("write config.json: {e}")))?;
    Ok(())
}

/// Get the network flag for the container runtime.
pub(crate) fn network_mode(config: &SandboxConfig) -> &'static str {
    if config.policy.network.enabled {
        "host"
    } else {
        "none"
    }
}

/// Generate a unique container ID.
pub(crate) fn container_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().as_simple())
}

/// Build environment variable list for OCI process.
pub(crate) fn build_env(config: &SandboxConfig) -> Vec<String> {
    let mut env = vec![
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into(),
        "TERM=xterm".into(),
    ];
    for (k, v) in &config.env {
        env.push(format!("{k}={v}"));
    }
    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn network_mode_disabled() {
        let config = SandboxConfig::builder()
            .backend(Backend::Process)
            .network(false)
            .build();
        assert_eq!(network_mode(&config), "none");
    }

    #[test]
    fn network_mode_enabled() {
        let mut config = SandboxConfig::builder().backend(Backend::Process).build();
        config.policy.network.enabled = true;
        assert_eq!(network_mode(&config), "host");
    }

    #[test]
    fn container_id_format() {
        let id = container_id("kavach");
        assert!(id.starts_with("kavach-"));
        assert!(id.len() > 10);
    }

    #[test]
    fn env_includes_defaults() {
        let config = SandboxConfig::builder().backend(Backend::Process).build();
        let env = build_env(&config);
        assert!(env.iter().any(|e| e.starts_with("PATH=")));
    }

    #[cfg(any(feature = "gvisor", feature = "oci"))]
    #[test]
    fn generate_spec_basic() {
        let config = SandboxConfig::builder().backend(Backend::Process).build();
        let spec = generate_spec(&config).unwrap();
        assert_eq!(spec.version(), "1.0.2");
    }

    #[cfg(any(feature = "gvisor", feature = "oci"))]
    #[test]
    fn generate_spec_with_limits() {
        use crate::policy::SandboxPolicy;
        let config = SandboxConfig::builder()
            .backend(Backend::Process)
            .policy(SandboxPolicy::strict())
            .build();
        let spec = generate_spec(&config).unwrap();
        let linux = spec.linux().as_ref().unwrap();
        let resources = linux.resources().as_ref().unwrap();
        assert!(resources.memory().is_some());
        assert!(resources.pids().is_some());
    }
}
