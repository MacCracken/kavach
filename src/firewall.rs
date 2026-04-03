//! Firewall policy integration — bridges nein's firewall engine with kavach sandbox policy.
//!
//! Provides convenience functions for building nftables firewalls from kavach's
//! `NetworkPolicy` and applying them to sandbox network namespaces.
//!
//! Requires the `nein` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use kavach::firewall;
//!
//! // Build a sandbox firewall from kavach's network policy
//! let fw = firewall::sandbox_firewall()
//!     .allow_outbound_tcp(443)
//!     .allow_outbound_tcp(80)
//!     .allow_inbound_tcp(8080)
//!     .restrict_outbound_to(&["10.0.0.0/8"])
//!     .build();
//!
//! println!("{}", fw.render());
//! ```

use nein::chain::{Chain, ChainType, Hook, Policy};
use nein::rule::{self, Match, Protocol, Rule, Verdict};
use nein::table::{Family, Table};

/// Fluent builder for sandbox firewall rules.
///
/// Wraps nein's rule/chain/table types into a sandbox-focused API.
/// Default: drop inbound, accept outbound, allow established + loopback + DNS.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SandboxFirewallBuilder {
    inbound_policy: Policy,
    outbound_policy: Policy,
    allowed_inbound_tcp: Vec<u16>,
    allowed_inbound_udp: Vec<u16>,
    allowed_outbound_tcp: Vec<u16>,
    allowed_outbound_udp: Vec<u16>,
    allowed_outbound_hosts: Vec<String>,
    allow_dns: bool,
    table_name: String,
}

impl Default for SandboxFirewallBuilder {
    fn default() -> Self {
        Self {
            inbound_policy: Policy::Drop,
            outbound_policy: Policy::Accept,
            allowed_inbound_tcp: Vec::new(),
            allowed_inbound_udp: Vec::new(),
            allowed_outbound_tcp: Vec::new(),
            allowed_outbound_udp: Vec::new(),
            allowed_outbound_hosts: Vec::new(),
            allow_dns: true,
            table_name: "kavach_sandbox".to_string(),
        }
    }
}

/// Create a new sandbox firewall builder with secure defaults.
#[must_use]
pub fn sandbox_firewall() -> SandboxFirewallBuilder {
    SandboxFirewallBuilder::default()
}

/// Create a fully locked down firewall — drop all inbound and outbound.
#[must_use]
pub fn lockdown_firewall() -> nein::Firewall {
    SandboxFirewallBuilder {
        outbound_policy: Policy::Drop,
        allow_dns: false,
        ..Default::default()
    }
    .build()
}

/// Create a permissive firewall — accept all, useful for development.
#[must_use]
pub fn permissive_firewall() -> nein::Firewall {
    SandboxFirewallBuilder {
        inbound_policy: Policy::Accept,
        outbound_policy: Policy::Accept,
        ..Default::default()
    }
    .build()
}

impl SandboxFirewallBuilder {
    /// Allow inbound TCP on a port.
    #[must_use]
    pub fn allow_inbound_tcp(mut self, port: u16) -> Self {
        self.allowed_inbound_tcp.push(port);
        self
    }

    /// Allow inbound UDP on a port.
    #[must_use]
    pub fn allow_inbound_udp(mut self, port: u16) -> Self {
        self.allowed_inbound_udp.push(port);
        self
    }

    /// Allow outbound TCP on a port.
    #[must_use]
    pub fn allow_outbound_tcp(mut self, port: u16) -> Self {
        self.allowed_outbound_tcp.push(port);
        self
    }

    /// Allow outbound UDP on a port.
    #[must_use]
    pub fn allow_outbound_udp(mut self, port: u16) -> Self {
        self.allowed_outbound_udp.push(port);
        self
    }

    /// Restrict outbound traffic to specific host CIDRs.
    ///
    /// When set, switches outbound policy to drop and only allows
    /// traffic to the listed CIDRs (plus explicitly allowed ports).
    #[must_use]
    pub fn restrict_outbound_to(mut self, hosts: &[&str]) -> Self {
        self.outbound_policy = Policy::Drop;
        self.allowed_outbound_hosts
            .extend(hosts.iter().map(|h| h.to_string()));
        self
    }

    /// Set custom inbound policy.
    #[must_use]
    pub fn inbound_policy(mut self, policy: Policy) -> Self {
        self.inbound_policy = policy;
        self
    }

    /// Set custom outbound policy.
    #[must_use]
    pub fn outbound_policy(mut self, policy: Policy) -> Self {
        self.outbound_policy = policy;
        self
    }

    /// Disable automatic DNS (UDP 53) allow rule.
    #[must_use]
    pub fn no_dns(mut self) -> Self {
        self.allow_dns = false;
        self
    }

    /// Set the nftables table name.
    #[must_use]
    pub fn table_name(mut self, name: impl Into<String>) -> Self {
        self.table_name = name.into();
        self
    }

    /// Build the nein `Firewall`.
    #[must_use]
    pub fn build(self) -> nein::Firewall {
        let mut fw = nein::Firewall::new();
        let mut table = Table::new(&self.table_name, Family::Inet);

        // Input chain
        let mut input = Chain::base(
            "input",
            ChainType::Filter,
            Hook::Input,
            0,
            self.inbound_policy,
        );
        input.add_rule(rule::allow_established());
        input.add_rule(Rule::new(Verdict::Accept).matching(Match::Iif("lo".to_string())));

        for port in &self.allowed_inbound_tcp {
            input.add_rule(rule::allow_tcp(*port));
        }
        for port in &self.allowed_inbound_udp {
            input.add_rule(rule::allow_udp(*port));
        }

        // Output chain
        let mut output = Chain::base(
            "output",
            ChainType::Filter,
            Hook::Output,
            0,
            self.outbound_policy,
        );
        output.add_rule(rule::allow_established());
        output.add_rule(Rule::new(Verdict::Accept).matching(Match::Oif("lo".to_string())));

        if self.allow_dns {
            output.add_rule(
                Rule::new(Verdict::Accept)
                    .matching(Match::Protocol(Protocol::Udp))
                    .matching(Match::DPort(53)),
            );
        }

        for port in &self.allowed_outbound_tcp {
            if self.allowed_outbound_hosts.is_empty() {
                output.add_rule(rule::allow_tcp(*port));
            } else {
                for host in &self.allowed_outbound_hosts {
                    output.add_rule(
                        Rule::new(Verdict::Accept)
                            .matching(Match::Protocol(Protocol::Tcp))
                            .matching(Match::DPort(*port))
                            .matching(Match::DestAddr(host.clone())),
                    );
                }
            }
        }
        for port in &self.allowed_outbound_udp {
            output.add_rule(rule::allow_udp(*port));
        }
        for host in &self.allowed_outbound_hosts {
            // Allow any traffic to these hosts (beyond specific ports above)
            if self.allowed_outbound_tcp.is_empty() {
                output.add_rule(Rule::new(Verdict::Accept).matching(Match::DestAddr(host.clone())));
            }
        }

        table.add_chain(input);
        table.add_chain(output);
        fw.add_table(table);
        fw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_builder_renders() {
        let fw = sandbox_firewall().build();
        let rendered = fw.render();
        assert!(rendered.contains("table inet kavach_sandbox"));
        assert!(rendered.contains("policy drop")); // inbound
        assert!(rendered.contains("policy accept")); // outbound
        assert!(rendered.contains("ct state"));
        assert!(rendered.contains("dport 53")); // DNS
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn lockdown_renders() {
        let fw = lockdown_firewall();
        let rendered = fw.render();
        assert_eq!(rendered.matches("policy drop").count(), 2);
        assert!(!rendered.contains("dport 53")); // no DNS
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn permissive_renders() {
        let fw = permissive_firewall();
        let rendered = fw.render();
        assert_eq!(rendered.matches("policy accept").count(), 2);
        assert!(fw.validate().is_ok());
    }

    #[test]
    fn inbound_tcp_ports() {
        let fw = sandbox_firewall()
            .allow_inbound_tcp(8080)
            .allow_inbound_tcp(443)
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("dport 8080"));
        assert!(rendered.contains("dport 443"));
    }

    #[test]
    fn outbound_host_restriction() {
        let fw = sandbox_firewall()
            .allow_outbound_tcp(443)
            .restrict_outbound_to(&["10.0.0.0/8", "192.168.0.0/16"])
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("10.0.0.0/8"));
        assert!(rendered.contains("192.168.0.0/16"));
        assert!(rendered.contains("dport 443"));
        // Outbound policy should be drop (allowlist mode)
        let output_section = &rendered[rendered.find("chain output").unwrap()..];
        assert!(output_section.contains("policy drop"));
    }

    #[test]
    fn no_dns() {
        let fw = sandbox_firewall().no_dns().build();
        let rendered = fw.render();
        assert!(!rendered.contains("dport 53"));
    }

    #[test]
    fn custom_table_name() {
        let fw = sandbox_firewall().table_name("my_agent").build();
        let rendered = fw.render();
        assert!(rendered.contains("table inet my_agent"));
    }

    #[test]
    fn udp_ports() {
        let fw = sandbox_firewall()
            .allow_inbound_udp(5060)
            .allow_outbound_udp(123)
            .build();
        let rendered = fw.render();
        assert!(rendered.contains("dport 5060"));
        assert!(rendered.contains("dport 123"));
    }

    #[test]
    fn validates_ok() {
        let fw = sandbox_firewall()
            .allow_inbound_tcp(80)
            .allow_outbound_tcp(443)
            .restrict_outbound_to(&["10.0.0.0/8"])
            .build();
        assert!(fw.validate().is_ok());
    }
}
