//! Firecracker VM configuration — JSON config generation from SandboxConfig.

use serde::{Deserialize, Serialize};

use crate::lifecycle::SandboxConfig;

/// Firecracker VM configuration (written as JSON for --config-file).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmConfig {
    /// Kernel and boot arguments.
    pub boot_source: BootSource,
    /// Block devices (rootfs, data volumes).
    pub drives: Vec<Drive>,
    /// vCPU and memory configuration.
    pub machine_config: MachineConfig,
    /// Optional TAP network interfaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<Vec<NetworkInterface>>,
    /// Optional vsock device for host-guest IPC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock: Option<VsockConfig>,
}

/// Kernel boot source configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootSource {
    /// Path to the uncompressed kernel image (vmlinux).
    pub kernel_image_path: String,
    /// Kernel command-line boot arguments.
    pub boot_args: String,
}

/// Block device (drive) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    /// Unique identifier for this drive.
    pub drive_id: String,
    /// Path to the drive image on the host.
    pub path_on_host: String,
    /// Whether this is the root device.
    pub is_root_device: bool,
    /// Whether the drive is read-only.
    pub is_read_only: bool,
}

/// Virtual machine hardware configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Memory size in MiB.
    pub mem_size_mib: u64,
    /// Whether simultaneous multithreading is enabled.
    pub smt: bool,
}

/// TAP network interface configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Unique identifier for this interface.
    pub iface_id: String,
    /// MAC address assigned to the guest.
    pub guest_mac: String,
    /// Host TAP device name.
    pub host_dev_name: String,
}

/// Vsock device configuration for host-guest communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockConfig {
    /// Guest CID (Context Identifier).
    pub guest_cid: u32,
    /// Path to the Unix domain socket on the host.
    pub uds_path: String,
}

/// Default boot args for minimal Linux kernel.
const DEFAULT_BOOT_ARGS: &str =
    "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=1 init=/sbin/overlay-init";

/// Firecracker-specific configuration derived from SandboxConfig.
#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    /// Path to uncompressed Linux kernel (vmlinux).
    pub kernel_path: String,
    /// Path to root filesystem image (ext4).
    pub rootfs_path: String,
    /// Number of vCPUs.
    pub vcpu_count: u32,
    /// Memory size in MiB.
    pub mem_size_mib: u64,
    /// Custom boot args (None = use defaults).
    pub boot_args: Option<String>,
    /// Enable vsock for host-guest IPC.
    pub vsock_cid: Option<u32>,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            kernel_path: "/var/lib/kavach/vmlinux".into(),
            rootfs_path: "/var/lib/kavach/rootfs.ext4".into(),
            vcpu_count: 1,
            mem_size_mib: 128,
            boot_args: None,
            vsock_cid: None,
        }
    }
}

impl FirecrackerConfig {
    /// Derive Firecracker config from sandbox policy.
    pub fn from_sandbox_config(config: &SandboxConfig) -> Self {
        let mut fc = Self::default();

        // Map memory limit
        if let Some(mb) = config.policy.memory_limit_mb {
            fc.mem_size_mib = mb;
        }

        // Map CPU limit to vCPU count (round up)
        if let Some(cpu) = config.policy.cpu_limit {
            fc.vcpu_count = (cpu.ceil() as u32).max(1);
        }

        fc
    }

    /// Generate the VmConfig JSON structure.
    pub fn to_vm_config(&self, workdir: &std::path::Path) -> VmConfig {
        let vsock_path = workdir.join("vsock.sock");

        VmConfig {
            boot_source: BootSource {
                kernel_image_path: self.kernel_path.clone(),
                boot_args: self
                    .boot_args
                    .clone()
                    .unwrap_or_else(|| DEFAULT_BOOT_ARGS.to_string()),
            },
            drives: vec![Drive {
                drive_id: "rootfs".into(),
                path_on_host: self.rootfs_path.clone(),
                is_root_device: true,
                is_read_only: true,
            }],
            machine_config: MachineConfig {
                vcpu_count: self.vcpu_count,
                mem_size_mib: self.mem_size_mib,
                smt: false,
            },
            network_interfaces: None, // TAP setup handled externally
            vsock: self.vsock_cid.map(|cid| VsockConfig {
                guest_cid: cid,
                uds_path: vsock_path.to_string_lossy().into_owned(),
            }),
        }
    }

    /// Write the VM config JSON to the workdir.
    pub fn write_config(&self, workdir: &std::path::Path) -> crate::Result<std::path::PathBuf> {
        let vm_config = self.to_vm_config(workdir);
        let config_path = workdir.join("firecracker.json");
        let json = serde_json::to_string_pretty(&vm_config)
            .map_err(|e| crate::KavachError::CreationFailed(format!("FC config: {e}")))?;
        std::fs::write(&config_path, json)
            .map_err(|e| crate::KavachError::CreationFailed(format!("write FC config: {e}")))?;
        Ok(config_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn default_config() {
        let fc = FirecrackerConfig::default();
        assert_eq!(fc.vcpu_count, 1);
        assert_eq!(fc.mem_size_mib, 128);
        assert!(fc.vsock_cid.is_none());
    }

    #[test]
    fn from_sandbox_config_memory() {
        let mut config = SandboxConfig::builder()
            .backend(Backend::Firecracker)
            .build();
        config.policy.memory_limit_mb = Some(256);
        let fc = FirecrackerConfig::from_sandbox_config(&config);
        assert_eq!(fc.mem_size_mib, 256);
    }

    #[test]
    fn from_sandbox_config_cpu() {
        let mut config = SandboxConfig::builder()
            .backend(Backend::Firecracker)
            .build();
        config.policy.cpu_limit = Some(2.5);
        let fc = FirecrackerConfig::from_sandbox_config(&config);
        assert_eq!(fc.vcpu_count, 3); // ceil(2.5)
    }

    #[test]
    fn vm_config_json() {
        let fc = FirecrackerConfig::default();
        let vm = fc.to_vm_config(std::path::Path::new("/tmp"));
        let json = serde_json::to_string(&vm).unwrap();
        assert!(json.contains("boot-source"));
        assert!(json.contains("machine-config"));
        assert!(json.contains("rootfs"));
    }

    #[test]
    fn vm_config_with_vsock() {
        let fc = FirecrackerConfig {
            vsock_cid: Some(3),
            ..Default::default()
        };
        let vm = fc.to_vm_config(std::path::Path::new("/tmp"));
        assert!(vm.vsock.is_some());
        assert_eq!(vm.vsock.unwrap().guest_cid, 3);
    }

    #[test]
    fn vm_config_no_network_by_default() {
        let fc = FirecrackerConfig::default();
        let vm = fc.to_vm_config(std::path::Path::new("/tmp"));
        assert!(vm.network_interfaces.is_none());
    }

    #[test]
    fn serde_roundtrip() {
        let fc = FirecrackerConfig::default();
        let vm = fc.to_vm_config(std::path::Path::new("/tmp"));
        let json = serde_json::to_string(&vm).unwrap();
        let back: VmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.machine_config.vcpu_count, 1);
        assert_eq!(back.machine_config.mem_size_mib, 128);
    }
}
