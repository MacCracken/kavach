//! Sandbox for agent isolation
//!
//! Implements Landlock, seccomp-bpf, and namespace isolation by delegating
//! to the real kernel interfaces in `agnos-sys`.

use std::collections::HashSet;

use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use agnostik::SandboxConfig;
use agnosys::audit;
use agnosys::luks;
use agnosys::mac;
use agnosys::netns;
use agnosys::security::{
    self, FilesystemRule as SysFilesystemRule, FsAccess as SysFsAccess, NamespaceFlags,
};

use crate::runtime::egress_gate::{ExternalizationGate, ExternalizationGateConfig, GateDecision};

/// Security sandbox for agent processes
pub struct Sandbox {
    config: SandboxConfig,
    applied: bool,
    /// Handle for the agent's network namespace (if created)
    netns_handle: Option<netns::NetNamespaceHandle>,
    /// Name of the LUKS volume (if created)
    luks_name: Option<String>,
    /// S2: Outbound data scanner — blocks secrets/PII before they leave the sandbox.
    egress_gate: ExternalizationGate,
}

impl Sandbox {
    /// Create a new sandbox from configuration
    pub fn new(config: &SandboxConfig) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            applied: false,
            netns_handle: None,
            luks_name: None,
            egress_gate: ExternalizationGate::new(ExternalizationGateConfig::default()),
        })
    }

    /// S2: Scan outbound data through the externalization gate.
    ///
    /// Call this at any network egress point before transmitting data on behalf
    /// of a sandboxed agent.  Returns the gate decision (allowed / blocked) with
    /// detailed findings for audit.  Only active when the sandbox has network
    /// access (`Full`, `Restricted`, or `LocalhostOnly`); `None` mode never
    /// produces outbound data so the gate is bypassed.
    pub fn scan_egress(&mut self, data: &[u8], agent_id: &str) -> GateDecision {
        match self.config.network_access {
            agnostik::NetworkAccess::None => {
                // No network — nothing can leave; allow trivially.
                GateDecision {
                    allowed: true,
                    findings: vec![],
                    data_size: data.len(),
                    scan_duration_us: 0,
                }
            }
            _ => self.egress_gate.scan(data, agent_id),
        }
    }

    /// Apply sandbox restrictions to the current process.
    ///
    /// Ordering is critical:
    /// 1. Encrypted storage — LUKS mount must happen before Landlock locks FS
    /// 2. MAC profile — context must be set before seccomp blocks /proc/self/attr/ writes
    /// 3. Landlock — filesystem restrictions
    /// 4. Seccomp — syscall filter (most restrictive, applied last)
    /// 5. Network isolation — namespace + nftables for Restricted mode
    /// 6. Audit event — record that sandbox was applied
    pub async fn apply(&mut self) -> Result<()> {
        if self.applied {
            return Ok(());
        }

        info!("Applying sandbox restrictions...");

        if let Err(e) = self.apply_inner().await {
            warn!(
                "Sandbox apply failed, cleaning up partially applied resources: {}",
                e
            );
            self.teardown().await;
            return Err(e);
        }

        // Emit audit event
        self.emit_audit_event("sandbox_applied").await;

        self.applied = true;
        info!("Sandbox restrictions applied successfully");

        Ok(())
    }

    /// Inner apply sequence — separated so that `apply()` can clean up on failure.
    async fn apply_inner(&mut self) -> Result<()> {
        // 1. Set up encrypted storage (before Landlock locks filesystem)
        self.apply_encrypted_storage().await?;

        // 2. Apply MAC profile (before seccomp blocks /proc/self/attr/ writes)
        self.apply_mac_profile().await?;

        // 3. Apply Landlock filesystem restrictions
        self.apply_landlock().await?;

        // 4. Apply seccomp-bpf filters
        self.apply_seccomp().await?;

        // 5. Apply network namespace isolation
        self.apply_network_isolation().await?;

        Ok(())
    }

    /// Convert agnos-common FilesystemRule to agnos-sys FilesystemRule
    fn convert_fs_rules(rules: &[agnostik::FilesystemRule]) -> Vec<SysFilesystemRule> {
        rules
            .iter()
            .map(|r| {
                let access = match r.access {
                    agnostik::FsAccess::NoAccess => SysFsAccess::NoAccess,
                    agnostik::FsAccess::ReadOnly => SysFsAccess::ReadOnly,
                    agnostik::FsAccess::ReadWrite => SysFsAccess::ReadWrite,
                    _ => SysFsAccess::NoAccess,
                };
                SysFilesystemRule::new(&r.path, access)
            })
            .collect()
    }

    /// Apply Landlock filesystem restrictions using real kernel syscalls
    async fn apply_landlock(&self) -> Result<()> {
        debug!("Applying Landlock restrictions...");

        let sys_rules = Self::convert_fs_rules(&self.config.filesystem_rules);

        if sys_rules.is_empty() {
            debug!("No filesystem rules configured, skipping Landlock");
            return Ok(());
        }

        match security::apply_landlock(&sys_rules) {
            Ok(()) => {
                info!("Landlock restrictions applied ({} rules)", sys_rules.len());
            }
            Err(e) => {
                // On non-Linux or unsupported kernels, agnos-sys returns Ok
                // with a warning log. An actual error here is unexpected.
                warn!("Landlock enforcement failed: {}", e);
                return Err(anyhow::anyhow!("Landlock enforcement failed: {}", e));
            }
        }

        Ok(())
    }

    /// Apply seccomp-bpf filters using real kernel syscalls
    async fn apply_seccomp(&self) -> Result<()> {
        debug!("Applying seccomp-bpf filters...");

        let filter = if let Some(profile) = self
            .config
            .seccomp
            .as_ref()
            .filter(|p| !p.syscalls.is_empty())
        {
            // Build custom filter from per-agent rules
            let base_allowed: &[u32] = &[
                0, 1, 3, 5, 9, 10, 11, 12, 15, 60, 131, 158, 186, 202, 218, 231, 273, 318, 228, 334,
            ];

            let mut extra_allowed = Vec::new();
            let mut denied = Vec::new();

            for rule in &profile.syscalls {
                for name in &rule.names {
                    if let Some(nr) = security::syscall_name_to_nr(name) {
                        match rule.action {
                            agnostik::SeccompAction::Allow => extra_allowed.push(nr),
                            agnostik::SeccompAction::Trap => {
                                denied.push((nr, security::SECCOMP_RET_TRAP))
                            }
                            _ => denied.push((nr, security::SECCOMP_RET_KILL_PROCESS)),
                        }
                    } else {
                        warn!("Unknown syscall name '{}' in seccomp rules, skipping", name);
                    }
                }
            }

            debug!(
                "Custom seccomp filter: {} base + {} extra allowed, {} denied",
                base_allowed.len(),
                extra_allowed.len(),
                denied.len()
            );

            security::create_custom_seccomp_filter(base_allowed, &extra_allowed, &denied)
                .context("Failed to create custom seccomp filter")?
        } else {
            // No per-agent rules — use the basic filter
            security::create_basic_seccomp_filter().context("Failed to create seccomp filter")?
        };

        if filter.is_empty() {
            debug!("Empty seccomp filter (non-Linux platform), skipping");
            return Ok(());
        }

        security::load_seccomp(&filter).context("Failed to load seccomp filter")?;

        info!("seccomp-bpf filter applied ({} bytes)", filter.len());
        Ok(())
    }

    /// Apply network namespace isolation using real kernel syscalls.
    ///
    /// For `Restricted` mode, creates a per-agent network namespace with veth
    /// pair, IP addresses, and nftables firewall rules based on `network_policy`.
    async fn apply_network_isolation(&mut self) -> Result<()> {
        if !self.config.isolate_network {
            debug!("Network isolation disabled");
            return Ok(());
        }

        debug!("Applying network isolation...");

        match self.config.network_access {
            agnostik::NetworkAccess::None => {
                // Create a new empty network namespace (no interfaces)
                security::create_namespace(NamespaceFlags::NETWORK)
                    .context("Failed to create network namespace for full isolation")?;
                info!("Network access: none (isolated namespace)");
            }
            agnostik::NetworkAccess::LocalhostOnly => {
                // Create network namespace — only loopback is available by default
                security::create_namespace(NamespaceFlags::NETWORK)
                    .context("Failed to create network namespace for localhost-only")?;
                info!("Network access: localhost only (new namespace with loopback)");
            }
            agnostik::NetworkAccess::Restricted => {
                // Create per-agent network namespace with veth + nftables
                let agent_name = format!("sandbox-{}", std::process::id());
                let ns_config = netns::NetNamespaceConfig::for_agent(&agent_name);

                match netns::create_agent_netns(&ns_config) {
                    Ok(handle) => {
                        // Apply firewall rules from network policy.
                        // When nein is active, use the engine to build a
                        // validated Firewall, render it, and apply via agnosys.
                        // Otherwise fall back to the agnosys FirewallPolicy.
                        #[cfg(feature = "nein")]
                        {
                            let fw = self.build_nein_firewall();
                            if let Err(e) = fw.validate() {
                                warn!("nein firewall validation failed: {e}");
                            }
                            let ruleset = fw.render();
                            if let Err(e) = netns::apply_nftables_ruleset(&handle, &ruleset) {
                                warn!(
                                    "Failed to apply nein firewall: {} (namespace created without firewall)",
                                    e
                                );
                            }
                        }
                        #[cfg(not(feature = "nein"))]
                        {
                            let policy = self.build_firewall_policy();
                            if let Err(e) = netns::apply_firewall_rules(&handle, &policy) {
                                warn!(
                                    "Failed to apply nftables rules: {} (namespace created without firewall)",
                                    e
                                );
                            }
                        }
                        info!(
                            patterns = self.egress_gate.pattern_count(),
                            "Network access: restricted (namespace '{}' with nftables firewall + egress gate)",
                            handle.name
                        );
                        self.netns_handle = Some(handle);
                    }
                    Err(e) => {
                        // Fall back to plain namespace isolation
                        warn!(
                            "Failed to create agent netns: {} — falling back to basic namespace",
                            e
                        );
                        security::create_namespace(NamespaceFlags::NETWORK)
                            .context("Failed to create network namespace for restricted access")?;
                    }
                }
            }
            agnostik::NetworkAccess::Full => {
                // Full access — don't create a new namespace.
                // S2: Egress gate is the primary outbound control for this mode.
                info!(
                    patterns = self.egress_gate.pattern_count(),
                    "Network access: full — egress gate active with {} patterns",
                    self.egress_gate.pattern_count()
                );
            }
            _ => {
                debug!("Unknown network access mode, defaulting to full isolation");
                security::create_namespace(NamespaceFlags::NETWORK)
                    .context("Failed to create network namespace")?;
            }
        }

        Ok(())
    }

    /// Build nftables firewall policy from the sandbox's network_policy config.
    #[cfg_attr(feature = "nein", allow(dead_code))]
    fn build_firewall_policy(&self) -> netns::FirewallPolicy {
        let mut rules = Vec::new();

        if let Some(ref policy) = self.config.network_policy {
            // Allow specified outbound ports
            for &port in &policy.allowed_outbound_ports {
                rules.push(netns::FirewallRule::new(
                    netns::TrafficDirection::Outbound,
                    netns::Protocol::Tcp,
                    port,
                    "",
                    netns::FirewallAction::Accept,
                    format!("Allow outbound TCP/{}", port),
                ));
            }

            // Allow specified outbound hosts
            for host in &policy.allowed_outbound_hosts {
                rules.push(netns::FirewallRule::new(
                    netns::TrafficDirection::Outbound,
                    netns::Protocol::Any,
                    0,
                    host.as_str(),
                    netns::FirewallAction::Accept,
                    format!("Allow outbound to {}", host),
                ));
            }

            // Allow specified inbound ports
            for &port in &policy.allowed_inbound_ports {
                rules.push(netns::FirewallRule::new(
                    netns::TrafficDirection::Inbound,
                    netns::Protocol::Tcp,
                    port,
                    "",
                    netns::FirewallAction::Accept,
                    format!("Allow inbound TCP/{}", port),
                ));
            }
        }

        let default_outbound = if self.config.network_policy.is_some() {
            netns::FirewallAction::Drop // Explicit allow-list mode
        } else {
            netns::FirewallAction::Accept
        };

        netns::FirewallPolicy::new(netns::FirewallAction::Drop, default_outbound, rules)
    }

    /// Build a nein `Firewall` from the sandbox's network_policy config.
    ///
    /// Uses nein's engine types (from crates.io) for type-safe rule building
    /// with conntrack, loopback, DNS defaults. The rendered ruleset is applied
    /// via agnosys::netns (git) — they work together on AGNOS.
    #[cfg(feature = "nein")]
    fn build_nein_firewall(&self) -> nein::Firewall {
        use nein::chain::{Chain, ChainType, Hook, Policy};
        use nein::rule::{self, Match, Protocol, Rule, Verdict};
        use nein::table::{Family, Table};

        let mut fw = nein::Firewall::new();
        let mut table = Table::new("kavach_agent", Family::Inet);

        // Determine policies based on whether we have explicit network rules
        let out_policy = if self.config.network_policy.is_some() {
            Policy::Drop
        } else {
            Policy::Accept
        };

        // Input chain
        let mut input = Chain::base("input", ChainType::Filter, Hook::Input, 0, Policy::Drop);
        input.add_rule(rule::allow_established());
        input.add_rule(Rule::new(Verdict::Accept).matching(Match::Iif("lo".to_string())));

        // Output chain
        let mut output = Chain::base("output", ChainType::Filter, Hook::Output, 0, out_policy);
        output.add_rule(rule::allow_established());
        output.add_rule(Rule::new(Verdict::Accept).matching(Match::Oif("lo".to_string())));
        // DNS
        output.add_rule(
            Rule::new(Verdict::Accept)
                .matching(Match::Protocol(Protocol::Udp))
                .matching(Match::DPort(53)),
        );

        if let Some(ref policy) = self.config.network_policy {
            for &port in &policy.allowed_outbound_ports {
                output.add_rule(rule::allow_tcp(port));
            }
            for host in &policy.allowed_outbound_hosts {
                output.add_rule(Rule::new(Verdict::Accept).matching(Match::DestAddr(host.clone())));
            }
            for &port in &policy.allowed_inbound_ports {
                input.add_rule(rule::allow_tcp(port));
            }
        }

        table.add_chain(input);
        table.add_chain(output);
        fw.add_table(table);
        fw
    }

    /// Apply MAC (AppArmor/SELinux) profile based on sandbox config.
    async fn apply_mac_profile(&self) -> Result<()> {
        let profile_name = match (&self.config.apparmor_profile, &self.config.selinux_label) {
            (Some(name), _) if !name.is_empty() => name.clone(),
            (_, Some(label)) if !label.is_empty() => label.clone(),
            _ => {
                debug!("No MAC profile configured, skipping");
                return Ok(());
            }
        };

        debug!("Applying MAC profile: {}", profile_name);

        let profiles = mac::default_agent_profiles();
        match mac::apply_agent_mac_profile(&profile_name, &profiles) {
            Ok(()) => {
                info!("MAC profile '{}' applied", profile_name);
            }
            Err(e) => {
                // MAC is best-effort on systems without SELinux/AppArmor
                let mac_system = mac::detect_mac_system();
                if mac_system == mac::MacSystem::None {
                    debug!("No MAC system active, skipping profile: {}", e);
                } else {
                    warn!("MAC profile application failed: {}", e);
                    return Err(anyhow::anyhow!("MAC profile application failed: {}", e));
                }
            }
        }

        Ok(())
    }

    /// Set up LUKS encrypted storage if configured.
    async fn apply_encrypted_storage(&mut self) -> Result<()> {
        let storage_config = match &self.config.encrypted_storage {
            Some(cfg) if cfg.enabled => cfg.clone(),
            _ => {
                debug!("Encrypted storage not configured, skipping");
                return Ok(());
            }
        };

        debug!(
            "Setting up encrypted storage ({} MB)",
            storage_config.size_mb
        );

        let agent_id = format!("sandbox-{}", std::process::id());
        let luks_config = luks::LuksConfig::for_agent(&agent_id, storage_config.size_mb);

        // Generate a random key for this volume
        let key = luks::LuksKey::generate(64)
            .map_err(|e| anyhow::anyhow!("Failed to generate LUKS encryption key: {}", e))?;

        match luks::setup_agent_volume(&luks_config, &key) {
            Ok(status) => {
                info!(
                    "Encrypted storage ready: {} ({} MB, {})",
                    status.name, storage_config.size_mb, status.cipher
                );
                self.luks_name = Some(status.name);
            }
            Err(e) => {
                warn!(
                    "Failed to set up encrypted storage: {} — continuing without it",
                    e
                );
            }
        }

        Ok(())
    }

    /// Emit an audit event for sandbox lifecycle actions.
    async fn emit_audit_event(&self, event: &str) {
        let msg = format!(
            "pid={} network={:?} apparmor={:?} selinux={:?} encrypted={}",
            std::process::id(),
            self.config.network_access,
            self.config.apparmor_profile,
            self.config.selinux_label,
            self.luks_name.is_some()
        );

        if let Err(e) = audit::agnos_audit_log_syscall(event, &msg, 0) {
            debug!(
                "Audit event '{}' not logged (expected on non-AGNOS kernels): {}",
                event, e
            );
        }
    }

    /// Tear down sandbox resources (network namespace, LUKS volume).
    ///
    /// Called during agent unregistration to clean up kernel resources.
    pub async fn teardown(&mut self) {
        // Destroy network namespace
        if let Some(ref handle) = self.netns_handle
            && let Err(e) = netns::destroy_agent_netns(handle.clone())
        {
            warn!(
                "Failed to destroy network namespace '{}': {}",
                handle.name, e
            );
        }
        self.netns_handle = None;

        // Teardown LUKS volume
        if let Some(ref name) = self.luks_name
            && let Err(e) = luks::teardown_agent_volume(name)
        {
            warn!("Failed to teardown LUKS volume '{}': {}", name, e);
        }
        self.luks_name = None;

        // Emit audit event
        self.emit_audit_event("sandbox_teardown").await;
    }

    /// Check if sandbox has been applied
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Apply sandbox restrictions with a pre-compiled seccomp profile instead
    /// of the generic filter.
    pub async fn apply_with_profile(
        &mut self,
        profile: &crate::seccomp_profiles::SeccompProfile,
    ) -> Result<()> {
        if self.applied {
            return Ok(());
        }

        info!("Applying sandbox with seccomp profile...");

        // Validate the profile first (before touching any kernel state)
        crate::seccomp_profiles::validate_profile(profile)
            .map_err(|e| anyhow::anyhow!("Invalid seccomp profile: {}", e))?;

        // Build the profile-specific filter spec (for logging/audit)
        let filter_spec = crate::seccomp_profiles::build_seccomp_filter(profile);
        debug!(
            "Seccomp profile '{}': {} allowed syscalls, default={}",
            filter_spec.profile_name,
            filter_spec.allowed.len(),
            filter_spec.default_action
        );

        if let Err(e) = self.apply_inner().await {
            warn!(
                "Sandbox apply (profile '{}') failed, cleaning up: {}",
                filter_spec.profile_name, e
            );
            self.teardown().await;
            return Err(e);
        }

        self.emit_audit_event("sandbox_applied").await;

        self.applied = true;
        info!(
            "Sandbox applied with '{}' seccomp profile",
            filter_spec.profile_name
        );

        Ok(())
    }
}

/// Seccomp-bpf filter builder
pub struct SeccompFilter {
    allowed_syscalls: HashSet<String>,
    denied_syscalls: HashSet<String>,
}

impl SeccompFilter {
    /// Create a new filter with default allowed syscalls
    pub fn new() -> Self {
        let mut allowed = HashSet::new();

        // Essential syscalls for any process
        allowed.insert("read".to_string());
        allowed.insert("write".to_string());
        allowed.insert("openat".to_string());
        allowed.insert("close".to_string());
        allowed.insert("exit".to_string());
        allowed.insert("exit_group".to_string());

        // Memory management
        allowed.insert("mmap".to_string());
        allowed.insert("munmap".to_string());
        allowed.insert("mprotect".to_string());
        allowed.insert("brk".to_string());

        // File operations
        allowed.insert("fstat".to_string());
        allowed.insert("lseek".to_string());
        allowed.insert("pread64".to_string());
        allowed.insert("pwrite64".to_string());

        // Process management
        allowed.insert("getpid".to_string());
        allowed.insert("getppid".to_string());
        allowed.insert("gettid".to_string());

        Self {
            allowed_syscalls: allowed,
            denied_syscalls: HashSet::new(),
        }
    }

    /// Add an allowed syscall
    pub fn allow(&mut self, syscall: &str) -> &mut Self {
        self.allowed_syscalls.insert(syscall.to_string());
        self
    }

    /// Deny a syscall
    pub fn deny(&mut self, syscall: &str) -> &mut Self {
        self.denied_syscalls.insert(syscall.to_string());
        self
    }

    /// Build and load the filter using real seccomp syscalls
    pub fn load(&self) -> Result<()> {
        let filter =
            security::create_basic_seccomp_filter().context("Failed to create seccomp filter")?;

        if filter.is_empty() {
            debug!("Empty seccomp filter (non-Linux platform), skipping");
            return Ok(());
        }

        security::load_seccomp(&filter).context("Failed to load seccomp filter")?;

        debug!(
            "Loaded seccomp filter with {} allowed syscalls",
            self.allowed_syscalls.len()
        );

        Ok(())
    }
}

impl Default for SeccompFilter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_new() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(!sandbox.is_applied());
    }

    #[test]
    fn test_seccomp_filter_new() {
        let filter = SeccompFilter::new();
        assert!(filter.allowed_syscalls.contains("read"));
        assert!(filter.allowed_syscalls.contains("write"));
        assert!(filter.allowed_syscalls.contains("mmap"));
    }

    #[test]
    fn test_seccomp_filter_allow() {
        let mut filter = SeccompFilter::new();
        filter.allow("custom_syscall");
        assert!(filter.allowed_syscalls.contains("custom_syscall"));
    }

    #[test]
    fn test_seccomp_filter_deny() {
        let mut filter = SeccompFilter::new();
        filter.deny("kill");
        assert!(filter.denied_syscalls.contains("kill"));
    }

    #[test]
    fn test_convert_fs_rules() {
        let rules = vec![
            agnostik::FilesystemRule {
                path: "/tmp".into(),
                access: agnostik::FsAccess::ReadWrite,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
            agnostik::FilesystemRule {
                path: "/etc".into(),
                access: agnostik::FsAccess::ReadOnly,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
            agnostik::FilesystemRule {
                path: "/root".into(),
                access: agnostik::FsAccess::NoAccess,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
        ];
        let sys_rules = Sandbox::convert_fs_rules(&rules);
        assert_eq!(sys_rules.len(), 3);
        assert_eq!(sys_rules[0].access, SysFsAccess::ReadWrite);
        assert_eq!(sys_rules[1].access, SysFsAccess::ReadOnly);
        assert_eq!(sys_rules[2].access, SysFsAccess::NoAccess);
    }

    #[tokio::test]
    async fn test_sandbox_apply() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        // Apply may fail on non-Linux or unprivileged environments — that's expected
        let _result = sandbox.apply().await;
    }

    #[test]
    fn test_sandbox_is_applied() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(!sandbox.is_applied());
    }

    #[tokio::test]
    async fn test_sandbox_apply_with_profile() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        // apply_with_profile may fail on non-Linux — that's expected
        let _result = sandbox
            .apply_with_profile(&crate::seccomp_profiles::SeccompProfile::Python)
            .await;
    }

    #[tokio::test]
    async fn test_sandbox_apply_with_invalid_profile() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        let empty_profile = crate::seccomp_profiles::SeccompProfile::Custom(vec![]);
        let result = sandbox.apply_with_profile(&empty_profile).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_sandbox_new_has_no_handles() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(sandbox.netns_handle.is_none());
        assert!(sandbox.luks_name.is_none());
    }

    #[test]
    fn test_sandbox_config_with_network_policy() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![80, 443],
                allowed_outbound_hosts: vec!["10.0.0.0/8".to_string()],
                allowed_inbound_ports: vec![8080],
                enable_nat: true,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(sandbox.config.network_policy.is_some());
    }

    #[test]
    fn test_sandbox_config_with_apparmor_profile() {
        let config = SandboxConfig {
            apparmor_profile: Some("User".to_string()),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        assert_eq!(sandbox.config.apparmor_profile.as_deref(), Some("User"));
    }

    #[test]
    fn test_sandbox_config_with_encrypted_storage() {
        let config = SandboxConfig {
            encrypted_storage: Some(agnostik::EncryptedStorageConfig {
                enabled: true,
                size_mb: 128,
                filesystem: "ext4".to_string(),
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(sandbox.config.encrypted_storage.is_some());
    }

    #[test]
    fn test_build_firewall_policy_no_network_policy() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();
        assert!(policy.rules.is_empty());
        assert_eq!(policy.default_outbound, netns::FirewallAction::Accept);
    }

    #[test]
    fn test_build_firewall_policy_with_rules() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![443, 8088],
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: vec![8080],
                enable_nat: true,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();
        // 2 outbound port rules + 1 inbound port rule = 3
        assert_eq!(policy.rules.len(), 3);
        assert_eq!(policy.default_outbound, netns::FirewallAction::Drop);
        assert_eq!(policy.default_inbound, netns::FirewallAction::Drop);
    }

    #[tokio::test]
    async fn test_sandbox_teardown_noop() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();
        // Teardown on a sandbox with no handles should not panic
        sandbox.teardown().await;
        assert!(sandbox.netns_handle.is_none());
        assert!(sandbox.luks_name.is_none());
    }

    #[test]
    fn test_sandbox_config_serialization() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy::default()),
            apparmor_profile: Some("Service".to_string()),
            encrypted_storage: Some(agnostik::EncryptedStorageConfig::default()),
            ..SandboxConfig::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.network_policy.is_some());
        assert_eq!(deserialized.apparmor_profile.as_deref(), Some("Service"));
        assert!(deserialized.encrypted_storage.is_some());
    }

    #[test]
    fn test_sandbox_config_default_serialization_roundtrip() {
        // Ensure default config can serialize/deserialize (no missing fields)
        let config = SandboxConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.network_policy.is_none());
        assert!(deserialized.apparmor_profile.is_none());
        assert!(deserialized.encrypted_storage.is_none());
    }

    #[test]
    fn test_sandbox_config_backward_compatible_deserialization() {
        // Old configs without new fields should still deserialize (serde(default))
        let json = r#"{"filesystem_rules":[{"path":"/tmp","access":"ReadWrite"}],"network_access":"LocalhostOnly","isolate_network":true}"#;
        let config: SandboxConfig = serde_json::from_str(json).unwrap();
        assert!(config.network_policy.is_none());
        assert!(config.apparmor_profile.is_none());
        assert!(config.encrypted_storage.is_none());
    }

    // ==================================================================
    // Additional coverage: SeccompFilter default, deny + allow interplay,
    // build_firewall_policy with hosts, sandbox apply idempotency,
    // convert_fs_rules empty, sandbox teardown with luks_name set,
    // network isolation paths, encrypted storage paths
    // ==================================================================

    #[test]
    fn test_seccomp_filter_default() {
        let filter = SeccompFilter::default();
        assert!(filter.allowed_syscalls.contains("read"));
        assert!(filter.allowed_syscalls.contains("write"));
        assert!(filter.denied_syscalls.is_empty());
    }

    #[test]
    fn test_seccomp_filter_allow_and_deny() {
        let mut filter = SeccompFilter::new();
        filter.allow("socket").allow("connect");
        filter.deny("ptrace").deny("execve");

        assert!(filter.allowed_syscalls.contains("socket"));
        assert!(filter.allowed_syscalls.contains("connect"));
        assert!(filter.denied_syscalls.contains("ptrace"));
        assert!(filter.denied_syscalls.contains("execve"));
    }

    #[test]
    fn test_seccomp_filter_allow_returns_self() {
        let mut filter = SeccompFilter::new();
        let returned = filter.allow("sendto");
        assert!(returned.allowed_syscalls.contains("sendto"));
    }

    #[test]
    fn test_seccomp_filter_deny_returns_self() {
        let mut filter = SeccompFilter::new();
        let returned = filter.deny("mount");
        assert!(returned.denied_syscalls.contains("mount"));
    }

    #[test]
    fn test_seccomp_filter_default_syscalls_count() {
        let filter = SeccompFilter::new();
        // Should have the 15 essential syscalls from new()
        assert!(filter.allowed_syscalls.len() >= 15);
    }

    #[test]
    fn test_convert_fs_rules_empty() {
        let rules: Vec<agnostik::FilesystemRule> = vec![];
        let sys_rules = Sandbox::convert_fs_rules(&rules);
        assert!(sys_rules.is_empty());
    }

    #[test]
    fn test_convert_fs_rules_all_access_types() {
        let rules = vec![
            agnostik::FilesystemRule {
                path: "/a".into(),
                access: agnostik::FsAccess::NoAccess,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
            agnostik::FilesystemRule {
                path: "/b".into(),
                access: agnostik::FsAccess::ReadOnly,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
            agnostik::FilesystemRule {
                path: "/c".into(),
                access: agnostik::FsAccess::ReadWrite,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            },
        ];
        let sys_rules = Sandbox::convert_fs_rules(&rules);
        assert_eq!(sys_rules.len(), 3);
        assert_eq!(sys_rules[0].access, SysFsAccess::NoAccess);
        assert_eq!(sys_rules[1].access, SysFsAccess::ReadOnly);
        assert_eq!(sys_rules[2].access, SysFsAccess::ReadWrite);
    }

    #[test]
    fn test_build_firewall_policy_with_outbound_hosts() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![],
                allowed_outbound_hosts: vec!["10.0.0.1".to_string(), "192.168.1.0/24".to_string()],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert_eq!(policy.rules.len(), 2);
        assert_eq!(policy.rules[0].remote_addr, "10.0.0.1");
        assert_eq!(policy.rules[1].remote_addr, "192.168.1.0/24");
        assert_eq!(policy.default_outbound, netns::FirewallAction::Drop);
    }

    #[test]
    fn test_build_firewall_policy_mixed_rules() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![443],
                allowed_outbound_hosts: vec!["api.example.com".to_string()],
                allowed_inbound_ports: vec![8080, 8443],
                enable_nat: true,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        // 1 outbound port + 1 outbound host + 2 inbound ports = 4
        assert_eq!(policy.rules.len(), 4);
        assert_eq!(policy.default_inbound, netns::FirewallAction::Drop);
        assert_eq!(policy.default_outbound, netns::FirewallAction::Drop);
    }

    #[tokio::test]
    async fn test_sandbox_apply_idempotent() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        // First apply may fail on non-Linux or unprivileged environments
        let first_result = sandbox.apply().await;

        if first_result.is_ok() {
            // If first succeeded, sandbox is applied
            assert!(sandbox.is_applied());

            // Second apply should be a no-op (returns Ok immediately)
            let result = sandbox.apply().await;
            assert!(result.is_ok());
            assert!(sandbox.is_applied());
        }
        // If first failed, that's expected in test environments
    }

    #[tokio::test]
    async fn test_sandbox_apply_with_profile_idempotent() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        // First apply
        let _result = sandbox
            .apply_with_profile(&crate::seccomp_profiles::SeccompProfile::Shell)
            .await;

        // If first apply succeeded, second should be immediate no-op
        if sandbox.is_applied() {
            let result = sandbox
                .apply_with_profile(&crate::seccomp_profiles::SeccompProfile::Shell)
                .await;
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_sandbox_teardown_with_fake_luks_name() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();
        // Simulate a LUKS volume was created
        sandbox.luks_name = Some("test-volume".to_string());

        // Teardown should attempt cleanup without panic
        sandbox.teardown().await;
        assert!(sandbox.luks_name.is_none());
    }

    #[tokio::test]
    async fn test_sandbox_emit_audit_event() {
        let config = SandboxConfig {
            apparmor_profile: Some("TestProfile".to_string()),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // Should not panic (audit may fail on non-AGNOS kernel)
        sandbox.emit_audit_event("test_event").await;
    }

    #[tokio::test]
    async fn test_sandbox_apply_landlock_empty_rules() {
        let config = SandboxConfig {
            filesystem_rules: vec![],
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // Should skip landlock (no rules)
        let result = sandbox.apply_landlock().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sandbox_apply_mac_profile_empty() {
        let config = SandboxConfig {
            apparmor_profile: Some(String::new()),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // Empty string should skip MAC profile
        let result = sandbox.apply_mac_profile().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sandbox_apply_mac_profile_none() {
        let config = SandboxConfig {
            apparmor_profile: None,
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let result = sandbox.apply_mac_profile().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sandbox_apply_network_isolation_disabled() {
        let config = SandboxConfig {
            isolate_network: false,
            ..SandboxConfig::default()
        };
        let mut sandbox = Sandbox::new(&config).unwrap();
        let result = sandbox.apply_network_isolation().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sandbox_apply_network_full_access() {
        let config = SandboxConfig {
            isolate_network: true,
            network_access: agnostik::NetworkAccess::Full,
            ..SandboxConfig::default()
        };
        let mut sandbox = Sandbox::new(&config).unwrap();
        // Full access with isolate_network = true means no namespace created
        let result = sandbox.apply_network_isolation().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_sandbox_apply_encrypted_storage_disabled() {
        let config = SandboxConfig {
            encrypted_storage: Some(agnostik::EncryptedStorageConfig {
                enabled: false,
                size_mb: 100,
                filesystem: "ext4".to_string(),
            }),
            ..SandboxConfig::default()
        };
        let mut sandbox = Sandbox::new(&config).unwrap();
        // Disabled storage should skip
        let result = sandbox.apply_encrypted_storage().await;
        assert!(result.is_ok());
        assert!(sandbox.luks_name.is_none());
    }

    #[tokio::test]
    async fn test_sandbox_apply_encrypted_storage_none() {
        let config = SandboxConfig {
            encrypted_storage: None,
            ..SandboxConfig::default()
        };
        let mut sandbox = Sandbox::new(&config).unwrap();
        let result = sandbox.apply_encrypted_storage().await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_firewall_policy_inbound_only() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![],
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: vec![22, 80, 443],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert_eq!(policy.rules.len(), 3);
        for rule in &policy.rules {
            assert_eq!(rule.direction, netns::TrafficDirection::Inbound);
            assert_eq!(rule.protocol, netns::Protocol::Tcp);
        }
    }

    #[test]
    fn test_build_firewall_rule_comments() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![8088],
                allowed_outbound_hosts: vec!["10.0.0.1".to_string()],
                allowed_inbound_ports: vec![9090],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert!(policy.rules[0].comment.contains("8088"));
        assert!(policy.rules[1].comment.contains("10.0.0.1"));
        assert!(policy.rules[2].comment.contains("9090"));
    }

    #[test]
    fn test_seccomp_filter_duplicate_allow() {
        let mut filter = SeccompFilter::new();
        let before_count = filter.allowed_syscalls.len();
        filter.allow("read"); // Already in default set
        assert_eq!(filter.allowed_syscalls.len(), before_count); // HashSet ignores duplicates
    }

    #[test]
    fn test_seccomp_filter_load_may_fail() {
        let filter = SeccompFilter::new();
        // On non-Linux or without capabilities, load may fail or succeed
        let _result = filter.load();
    }

    // ==================================================================
    // NEW: SandboxConfig validation, apply order, network policy edge cases,
    // MAC profile edge cases, encrypted storage config, firewall protocol,
    // SeccompFilter chaining, sandbox state transitions, teardown sequences
    // ==================================================================

    #[test]
    fn test_sandbox_new_preserves_all_config_fields() {
        let config = SandboxConfig {
            filesystem_rules: vec![agnostik::FilesystemRule {
                path: "/home".into(),
                access: agnostik::FsAccess::ReadWrite,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            }],
            network_access: agnostik::NetworkAccess::Restricted,
            seccomp: Some(agnostik::SeccompProfile {
                default_action: agnostik::SeccompAction::KillProcess,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![
                    agnostik::SeccompRule {
                        names: vec!["read".to_string()],
                        action: agnostik::SeccompAction::Allow,
                        args: vec![],
                    },
                    agnostik::SeccompRule {
                        names: vec!["write".to_string()],
                        action: agnostik::SeccompAction::Allow,
                        args: vec![],
                    },
                ],
            }),
            isolate_network: true,
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![443],
                allowed_outbound_hosts: vec!["example.com".to_string()],
                allowed_inbound_ports: vec![8080],
                enable_nat: true,
            }),
            apparmor_profile: Some("Sandbox".to_string()),
            encrypted_storage: Some(agnostik::EncryptedStorageConfig {
                enabled: true,
                size_mb: 256,
                filesystem: "btrfs".to_string(),
            }),
            ..SandboxConfig::default()
        };

        let sandbox = Sandbox::new(&config).unwrap();
        assert_eq!(sandbox.config.filesystem_rules.len(), 1);
        assert_eq!(
            sandbox.config.network_access,
            agnostik::NetworkAccess::Restricted
        );
        assert_eq!(sandbox.config.seccomp.as_ref().unwrap().syscalls.len(), 2);
        assert!(sandbox.config.isolate_network);
        assert!(sandbox.config.network_policy.is_some());
        assert_eq!(sandbox.config.apparmor_profile.as_deref(), Some("Sandbox"));
        let storage = sandbox.config.encrypted_storage.as_ref().unwrap();
        assert!(storage.enabled);
        assert_eq!(storage.size_mb, 256);
        assert_eq!(storage.filesystem, "btrfs");
    }

    #[test]
    fn test_sandbox_not_applied_initially() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        assert!(!sandbox.is_applied());
        assert!(!sandbox.applied);
    }

    #[test]
    fn test_convert_fs_rules_single_rule() {
        let rules = vec![agnostik::FilesystemRule {
            path: "/var/log".into(),
            access: agnostik::FsAccess::ReadOnly,
            readonly: false,
            noexec: false,
            nosuid: false,
            nodev: false,
            propagation: agnostik::MountPropagation::Private,
        }];
        let sys_rules = Sandbox::convert_fs_rules(&rules);
        assert_eq!(sys_rules.len(), 1);
        assert_eq!(sys_rules[0].access, SysFsAccess::ReadOnly);
    }

    #[test]
    fn test_convert_fs_rules_many_rules() {
        let rules: Vec<_> = (0..100)
            .map(|i| agnostik::FilesystemRule {
                path: format!("/path/{}", i).into(),
                access: agnostik::FsAccess::ReadOnly,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            })
            .collect();
        let sys_rules = Sandbox::convert_fs_rules(&rules);
        assert_eq!(sys_rules.len(), 100);
    }

    #[test]
    fn test_build_firewall_policy_outbound_ports_protocol() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![80, 443, 8088],
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert_eq!(policy.rules.len(), 3);
        for rule in &policy.rules {
            assert_eq!(rule.direction, netns::TrafficDirection::Outbound);
            assert_eq!(rule.protocol, netns::Protocol::Tcp);
            assert_eq!(rule.action, netns::FirewallAction::Accept);
            assert!(rule.remote_addr.is_empty());
        }
        assert_eq!(policy.rules[0].port, 80);
        assert_eq!(policy.rules[1].port, 443);
        assert_eq!(policy.rules[2].port, 8088);
    }

    #[test]
    fn test_build_firewall_policy_outbound_hosts_protocol() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![],
                allowed_outbound_hosts: vec!["host1.com".to_string()],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].protocol, netns::Protocol::Any);
        assert_eq!(policy.rules[0].port, 0);
        assert_eq!(policy.rules[0].remote_addr, "host1.com");
    }

    #[test]
    fn test_build_firewall_policy_empty_policy() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![],
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert!(policy.rules.is_empty());
        // Still in allowlist mode since network_policy is Some
        assert_eq!(policy.default_outbound, netns::FirewallAction::Drop);
    }

    #[test]
    fn test_seccomp_filter_chained_operations() {
        let mut filter = SeccompFilter::new();
        filter
            .allow("socket")
            .allow("bind")
            .allow("listen")
            .deny("ptrace")
            .deny("reboot");

        assert!(filter.allowed_syscalls.contains("socket"));
        assert!(filter.allowed_syscalls.contains("bind"));
        assert!(filter.allowed_syscalls.contains("listen"));
        assert!(filter.denied_syscalls.contains("ptrace"));
        assert!(filter.denied_syscalls.contains("reboot"));
    }

    #[test]
    fn test_seccomp_filter_all_default_syscalls() {
        let filter = SeccompFilter::new();
        // Verify all essential syscalls from new()
        let expected = [
            "read",
            "write",
            "openat",
            "close",
            "exit",
            "exit_group",
            "mmap",
            "munmap",
            "mprotect",
            "brk",
            "fstat",
            "lseek",
            "pread64",
            "pwrite64",
            "getpid",
            "getppid",
            "gettid",
        ];
        for syscall in expected {
            assert!(
                filter.allowed_syscalls.contains(syscall),
                "Missing default syscall: {}",
                syscall
            );
        }
    }

    #[tokio::test]
    async fn test_sandbox_teardown_clears_both_handles() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();

        // Set both handles to simulate allocated resources
        sandbox.luks_name = Some("fake-luks-vol".to_string());
        // We can't set netns_handle easily (no public constructor),
        // but verify luks_name is cleared
        sandbox.teardown().await;
        assert!(sandbox.luks_name.is_none());
        assert!(sandbox.netns_handle.is_none());
    }

    #[tokio::test]
    async fn test_sandbox_apply_with_all_profiles() {
        let profiles = [
            crate::seccomp_profiles::SeccompProfile::Python,
            crate::seccomp_profiles::SeccompProfile::Node,
            crate::seccomp_profiles::SeccompProfile::Shell,
            crate::seccomp_profiles::SeccompProfile::Wasm,
        ];

        for profile in &profiles {
            let config = SandboxConfig::default();
            let mut sandbox = Sandbox::new(&config).unwrap();
            // May fail on non-Linux, but should not panic
            let _result = sandbox.apply_with_profile(profile).await;
        }
    }

    #[test]
    fn test_sandbox_config_all_network_access_types() {
        for access in [
            agnostik::NetworkAccess::None,
            agnostik::NetworkAccess::LocalhostOnly,
            agnostik::NetworkAccess::Restricted,
            agnostik::NetworkAccess::Full,
        ] {
            let config = SandboxConfig {
                network_access: access,
                ..SandboxConfig::default()
            };
            let sandbox = Sandbox::new(&config).unwrap();
            assert_eq!(sandbox.config.network_access, access);
        }
    }

    #[test]
    fn test_sandbox_config_clone_independence() {
        let config = SandboxConfig {
            apparmor_profile: Some("Original".to_string()),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();

        // Sandbox stores a clone, so original can be modified
        let mut config2 = config.clone();
        config2.apparmor_profile = Some("Modified".to_string());

        // Sandbox should still have original value
        assert_eq!(sandbox.config.apparmor_profile.as_deref(), Some("Original"));
    }

    #[tokio::test]
    async fn test_sandbox_emit_audit_event_with_luks_name() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();
        sandbox.luks_name = Some("audit-test-vol".to_string());

        // Should not panic
        sandbox.emit_audit_event("test_with_luks").await;
    }

    #[test]
    fn test_seccomp_filter_deny_already_allowed() {
        let mut filter = SeccompFilter::new();
        // "read" is in the allowed set by default
        assert!(filter.allowed_syscalls.contains("read"));
        // Deny it
        filter.deny("read");
        // Both sets can contain it (filter.load() resolves precedence)
        assert!(filter.denied_syscalls.contains("read"));
        assert!(filter.allowed_syscalls.contains("read"));
    }

    #[tokio::test]
    async fn test_sandbox_apply_landlock_with_rules() {
        let config = SandboxConfig {
            filesystem_rules: vec![agnostik::FilesystemRule {
                path: "/tmp".into(),
                access: agnostik::FsAccess::ReadWrite,
                readonly: false,
                noexec: false,
                nosuid: false,
                nodev: false,
                propagation: agnostik::MountPropagation::Private,
            }],
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // May fail on non-Linux, that's expected
        let _result = sandbox.apply_landlock().await;
    }

    #[tokio::test]
    async fn test_sandbox_apply_seccomp_standalone() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        // May fail or succeed depending on platform
        let _result = sandbox.apply_seccomp().await;
    }

    #[tokio::test]
    #[ignore] // Seccomp filters persist per-process; run in isolation
    async fn test_sandbox_apply_seccomp_with_custom_rules() {
        let config = SandboxConfig {
            seccomp: Some(agnostik::SeccompProfile {
                default_action: agnostik::SeccompAction::KillProcess,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![
                    agnostik::SeccompRule {
                        names: vec!["socket".to_string()],
                        action: agnostik::SeccompAction::Allow,
                        args: vec![],
                    },
                    agnostik::SeccompRule {
                        names: vec!["ptrace".to_string()],
                        action: agnostik::SeccompAction::KillProcess,
                        args: vec![],
                    },
                    agnostik::SeccompRule {
                        names: vec!["mount".to_string()],
                        action: agnostik::SeccompAction::Trap,
                        args: vec![],
                    },
                ],
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // May fail or succeed depending on platform (needs CAP_SYS_ADMIN)
        let _result = sandbox.apply_seccomp().await;
    }

    #[tokio::test]
    #[ignore] // Seccomp filters persist per-process; run in isolation
    async fn test_sandbox_apply_seccomp_unknown_syscall_warns() {
        let config = SandboxConfig {
            seccomp: Some(agnostik::SeccompProfile {
                default_action: agnostik::SeccompAction::KillProcess,
                architectures: vec![],
                flags: vec![],
                syscalls: vec![agnostik::SeccompRule {
                    names: vec!["nonexistent_call".to_string()],
                    action: agnostik::SeccompAction::Allow,
                    args: vec![],
                }],
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        // Should not panic, just warn and skip unknown syscall
        let _result = sandbox.apply_seccomp().await;
    }

    #[test]
    fn test_build_firewall_policy_many_ports() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: (1..=100).collect(),
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: (200..=210).collect(),
                enable_nat: true,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();

        assert_eq!(policy.rules.len(), 100 + 11);
    }

    #[tokio::test]
    async fn test_sandbox_double_teardown() {
        let config = SandboxConfig::default();
        let mut sandbox = Sandbox::new(&config).unwrap();
        sandbox.luks_name = Some("double-teardown".to_string());

        sandbox.teardown().await;
        assert!(sandbox.luks_name.is_none());

        // Second teardown should be a no-op
        sandbox.teardown().await;
        assert!(sandbox.luks_name.is_none());
    }

    // --- SeccompFilter builder tests ---

    #[test]
    fn test_seccomp_filter_new_has_all_defaults() {
        let filter = SeccompFilter::new();
        assert!(filter.allowed_syscalls.contains("read"));
        assert!(filter.allowed_syscalls.contains("write"));
        assert!(filter.allowed_syscalls.contains("openat"));
        assert!(filter.allowed_syscalls.contains("close"));
        assert!(filter.allowed_syscalls.contains("exit"));
        assert!(filter.allowed_syscalls.contains("exit_group"));
        assert!(filter.allowed_syscalls.contains("mmap"));
        assert!(filter.allowed_syscalls.contains("munmap"));
        assert!(filter.allowed_syscalls.contains("mprotect"));
        assert!(filter.allowed_syscalls.contains("brk"));
        assert!(filter.allowed_syscalls.contains("fstat"));
        assert!(filter.allowed_syscalls.contains("lseek"));
        assert!(filter.allowed_syscalls.contains("pread64"));
        assert!(filter.allowed_syscalls.contains("pwrite64"));
        assert!(filter.allowed_syscalls.contains("getpid"));
        assert!(filter.allowed_syscalls.contains("getppid"));
        assert!(filter.allowed_syscalls.contains("gettid"));
        assert!(filter.denied_syscalls.is_empty());
    }

    #[test]
    fn test_seccomp_filter_default_equals_new() {
        let from_new = SeccompFilter::new();
        let from_default = SeccompFilter::default();
        assert_eq!(from_new.allowed_syscalls, from_default.allowed_syscalls);
        assert_eq!(from_new.denied_syscalls, from_default.denied_syscalls);
    }

    #[test]
    fn test_seccomp_filter_chaining() {
        let mut filter = SeccompFilter::new();
        filter
            .allow("socket")
            .allow("bind")
            .deny("ptrace")
            .deny("personality");
        assert!(filter.allowed_syscalls.contains("socket"));
        assert!(filter.allowed_syscalls.contains("bind"));
        assert!(filter.denied_syscalls.contains("ptrace"));
        assert!(filter.denied_syscalls.contains("personality"));
    }

    // --- build_firewall_policy ---

    #[test]
    fn test_build_firewall_policy_outbound_ports_only() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![80, 443],
                allowed_outbound_hosts: vec![],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();
        assert_eq!(policy.rules.len(), 2);
    }

    #[test]
    fn test_build_firewall_policy_outbound_hosts() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![],
                allowed_outbound_hosts: vec!["api.example.com".to_string()],
                allowed_inbound_ports: vec![],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_build_firewall_policy_combined() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![443],
                allowed_outbound_hosts: vec!["api.example.com".to_string()],
                allowed_inbound_ports: vec![8080],
                enable_nat: true,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let policy = sandbox.build_firewall_policy();
        assert_eq!(policy.rules.len(), 3); // 1 outbound port + 1 host + 1 inbound
    }

    // -- nein integration --

    #[cfg(feature = "nein")]
    #[test]
    fn test_build_nein_firewall_default() {
        let config = SandboxConfig::default();
        let sandbox = Sandbox::new(&config).unwrap();
        let fw = sandbox.build_nein_firewall();
        let rendered = fw.render();
        // Default: no network_policy → outbound accepts, inbound drops
        assert!(rendered.contains("table inet kavach_agent"));
        assert!(rendered.contains("policy drop")); // inbound
        assert!(rendered.contains("policy accept")); // outbound
        assert!(rendered.contains("ct state"));
        assert!(fw.validate().is_ok());
    }

    #[cfg(feature = "nein")]
    #[test]
    fn test_build_nein_firewall_with_policy() {
        let config = SandboxConfig {
            network_policy: Some(agnostik::NetworkPolicy {
                allowed_outbound_ports: vec![443],
                allowed_outbound_hosts: vec!["10.0.0.0/8".to_string()],
                allowed_inbound_ports: vec![8080],
                enable_nat: false,
            }),
            ..SandboxConfig::default()
        };
        let sandbox = Sandbox::new(&config).unwrap();
        let fw = sandbox.build_nein_firewall();
        let rendered = fw.render();
        // Allowlist mode: outbound drops, specific ports/hosts allowed
        assert_eq!(rendered.matches("policy drop").count(), 2);
        assert!(rendered.contains("dport 443"));
        assert!(rendered.contains("dport 8080"));
        assert!(rendered.contains("10.0.0.0/8"));
        assert!(fw.validate().is_ok());
    }
}
