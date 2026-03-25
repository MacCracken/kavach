//! Network TAP device setup — isolated networking for Firecracker VMs.
//!
//! Creates TAP devices with iptables-based isolation rules so each VM
//! gets its own network namespace with controlled connectivity.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// TAP device configuration for Firecracker VM networking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapConfig {
    /// TAP device name (e.g., "kavach-tap0").
    pub tap_name: String,
    /// Host-side IP address for the TAP interface.
    pub host_ip: String,
    /// Guest-side IP address.
    pub guest_ip: String,
    /// Subnet mask (e.g., "255.255.255.252" for /30).
    pub subnet_mask: String,
    /// Guest MAC address.
    pub guest_mac: String,
}

impl TapConfig {
    /// Create a TAP config for a VM with the given index.
    ///
    /// Uses a /30 subnet (4 addresses) per VM for isolation.
    #[must_use]
    pub fn for_vm(index: u16) -> Self {
        let base = 10 + (index as u32) * 4;
        Self {
            tap_name: format!("kavach-tap{index}"),
            host_ip: format!("172.16.0.{}", base + 1),
            guest_ip: format!("172.16.0.{}", base + 2),
            subnet_mask: "255.255.255.252".into(),
            guest_mac: format!("AA:FC:00:00:{:02X}:{:02X}", index >> 8, index & 0xFF),
        }
    }

    /// Set up the TAP device and configure iptables isolation.
    ///
    /// Requires root or CAP_NET_ADMIN.
    pub async fn setup(&self) -> crate::Result<()> {
        tracing::debug!(tap = %self.tap_name, host_ip = %self.host_ip, "setting up TAP device");

        // Create TAP device
        run_cmd("ip", &["tuntap", "add", &self.tap_name, "mode", "tap"]).await?;

        // Configure IP address
        let cidr = format!("{}/30", self.host_ip);
        run_cmd("ip", &["addr", "add", &cidr, "dev", &self.tap_name]).await?;

        // Bring up interface
        run_cmd("ip", &["link", "set", &self.tap_name, "up"]).await?;

        // iptables: default DROP for this TAP
        run_cmd(
            "iptables",
            &["-A", "FORWARD", "-i", &self.tap_name, "-j", "DROP"],
        )
        .await?;

        // iptables: allow established connections back
        run_cmd(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-i",
                &self.tap_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )
        .await?;

        tracing::debug!(tap = %self.tap_name, "TAP device configured");
        Ok(())
    }

    /// Tear down the TAP device and remove iptables rules.
    pub async fn teardown(&self) -> crate::Result<()> {
        tracing::debug!(tap = %self.tap_name, "tearing down TAP device");

        // Remove iptables rules (best-effort)
        let _ = run_cmd(
            "iptables",
            &["-D", "FORWARD", "-i", &self.tap_name, "-j", "DROP"],
        )
        .await;
        let _ = run_cmd(
            "iptables",
            &[
                "-D",
                "FORWARD",
                "-i",
                &self.tap_name,
                "-m",
                "state",
                "--state",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        )
        .await;

        // Delete TAP device
        let _ = run_cmd("ip", &["link", "del", &self.tap_name]).await;

        tracing::debug!(tap = %self.tap_name, "TAP device removed");
        Ok(())
    }

    /// Generate the Firecracker `NetworkInterface` config entry.
    #[must_use]
    pub fn to_network_interface(&self) -> super::config::NetworkInterface {
        super::config::NetworkInterface {
            iface_id: "eth0".into(),
            guest_mac: self.guest_mac.clone(),
            host_dev_name: self.tap_name.clone(),
        }
    }

    /// Generate guest-side boot args for network configuration.
    #[must_use]
    pub fn guest_boot_args(&self) -> String {
        format!(
            "ip={}::{}:{}::eth0:off",
            self.guest_ip, self.host_ip, self.subnet_mask
        )
    }

    /// Check if the TAP device currently exists.
    pub async fn exists(&self) -> bool {
        let path = format!("/sys/class/net/{}", self.tap_name);
        Path::new(&path).exists()
    }
}

/// Run a system command, returning an error on failure.
async fn run_cmd(program: &str, args: &[&str]) -> crate::Result<()> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| {
            crate::KavachError::ExecFailed(format!("{program} {}: {e}", args.join(" ")))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(crate::KavachError::ExecFailed(format!(
            "{program} failed: {stderr}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_config_for_vm() {
        let tap = TapConfig::for_vm(0);
        assert_eq!(tap.tap_name, "kavach-tap0");
        assert_eq!(tap.host_ip, "172.16.0.11");
        assert_eq!(tap.guest_ip, "172.16.0.12");
        assert_eq!(tap.subnet_mask, "255.255.255.252");
    }

    #[test]
    fn tap_config_sequential_ips() {
        let tap0 = TapConfig::for_vm(0);
        let tap1 = TapConfig::for_vm(1);
        assert_ne!(tap0.host_ip, tap1.host_ip);
        assert_ne!(tap0.guest_ip, tap1.guest_ip);
        assert_ne!(tap0.tap_name, tap1.tap_name);
    }

    #[test]
    fn network_interface_generation() {
        let tap = TapConfig::for_vm(0);
        let iface = tap.to_network_interface();
        assert_eq!(iface.host_dev_name, "kavach-tap0");
        assert_eq!(iface.iface_id, "eth0");
    }

    #[test]
    fn guest_boot_args() {
        let tap = TapConfig::for_vm(0);
        let args = tap.guest_boot_args();
        assert!(args.contains("172.16.0.12"));
        assert!(args.contains("172.16.0.11"));
    }

    #[test]
    fn serde_roundtrip() {
        let tap = TapConfig::for_vm(5);
        let json = serde_json::to_string(&tap).unwrap();
        let back: TapConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(tap.tap_name, back.tap_name);
        assert_eq!(tap.host_ip, back.host_ip);
    }

    #[test]
    fn mac_address_format() {
        let tap = TapConfig::for_vm(256);
        // 256 = 0x0100 → 01:00
        assert_eq!(tap.guest_mac, "AA:FC:00:00:01:00");
    }

    #[tokio::test]
    async fn tap_exists_false() {
        let tap = TapConfig::for_vm(9999);
        assert!(!tap.exists().await);
    }
}
