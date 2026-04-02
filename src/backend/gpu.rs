//! GPU passthrough for sandboxed workloads.
//!
//! Bridges ai-hwaccel's accelerator detection with kavach's sandbox policy
//! to safely expose GPU/NPU/TPU devices inside isolation boundaries.
//!
//! Given an [`ai_hwaccel::AcceleratorProfile`], this module computes:
//! - Device node paths (`/dev/nvidia0`, `/dev/dri/renderD128`, `/dev/accel0`)
//! - Required Landlock filesystem rules for device access
//! - Minimum driver version validation
//!
//! Requires the `gpu` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use kavach::backend::gpu::{GpuPassthrough, GpuPolicy};
//!
//! let passthrough = GpuPassthrough::detect_all();
//! for device in &passthrough.devices {
//!     println!("{}: {:?}", device.name, device.device_paths);
//! }
//!
//! // Generate Landlock rules for the first GPU
//! if let Some(device) = passthrough.devices.first() {
//!     let rules = device.to_landlock_rules();
//!     // Merge into sandbox policy...
//! }
//! ```

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::policy::LandlockRule;

/// A GPU/accelerator device prepared for sandbox passthrough.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GpuDevice {
    /// Human-readable device name (e.g. "NVIDIA RTX 4090", "AMD Radeon RX 7900").
    pub name: String,
    /// Device family.
    pub family: DeviceFamily,
    /// Numeric device index (0-based).
    pub device_id: u32,
    /// Device node paths that must be accessible inside the sandbox.
    pub device_paths: Vec<String>,
    /// Total device memory in bytes.
    pub memory_bytes: u64,
    /// Driver version string (if detected).
    pub driver_version: Option<String>,
}

/// Device family classification for passthrough policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum DeviceFamily {
    NvidiaGpu,
    AmdGpu,
    IntelGpu,
    GoogleTpu,
    AwsNeuron,
    AmdXdnaNpu,
    IntelNpu,
    QualcommAi,
    Cerebras,
    Other,
}

impl GpuDevice {
    /// Compute device node paths for an accelerator type and device ID.
    #[must_use]
    fn from_accelerator(
        accel_type: &ai_hwaccel::AcceleratorType,
        profile: &ai_hwaccel::AcceleratorProfile,
    ) -> Option<Self> {
        let device_name = profile
            .device_name
            .clone()
            .unwrap_or_else(|| format!("{accel_type:?}"));

        let (family, device_id, paths) = match accel_type {
            ai_hwaccel::AcceleratorType::CudaGpu { device_id } => {
                let mut paths = vec![
                    format!("/dev/nvidia{device_id}"),
                    "/dev/nvidiactl".to_string(),
                    "/dev/nvidia-uvm".to_string(),
                ];
                // nvidia-caps for MIG and compute mode
                if std::path::Path::new("/dev/nvidia-caps").exists() {
                    paths.push("/dev/nvidia-caps".to_string());
                }
                (DeviceFamily::NvidiaGpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::RocmGpu { device_id } => {
                let paths = enumerate_dri_render_nodes(*device_id);
                (DeviceFamily::AmdGpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::VulkanGpu { device_id } => {
                // Vulkan may be Intel or other — use DRI render nodes
                let paths = enumerate_dri_render_nodes(*device_id);
                (DeviceFamily::IntelGpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::IntelOneApi { device_id } => {
                let paths = enumerate_dri_render_nodes(*device_id);
                (DeviceFamily::IntelGpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::Tpu { device_id, .. } => {
                let paths = vec![format!("/dev/accel{device_id}")];
                (DeviceFamily::GoogleTpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::AwsNeuron { device_id, .. } => {
                let paths = vec![format!("/dev/neuron{device_id}")];
                (DeviceFamily::AwsNeuron, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::AmdXdnaNpu { device_id } => {
                let paths = vec![format!("/dev/accel{device_id}")];
                (DeviceFamily::AmdXdnaNpu, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::IntelNpu => {
                let paths = vec!["/dev/intel_npu".to_string()];
                (DeviceFamily::IntelNpu, 0, paths)
            }
            ai_hwaccel::AcceleratorType::QualcommAi100 { device_id } => {
                let paths = vec![format!("/dev/qaic_{device_id}")];
                (DeviceFamily::QualcommAi, *device_id, paths)
            }
            ai_hwaccel::AcceleratorType::CerebrasWse { device_id } => {
                let paths = vec![format!("/dev/cerebras{device_id}")];
                (DeviceFamily::Cerebras, *device_id, paths)
            }
            // CPU, Metal, Apple NPU, and other non-passthrough types
            _ => return None,
        };

        // Filter to paths that actually exist on this system
        let existing_paths: Vec<String> = paths
            .into_iter()
            .filter(|p| std::path::Path::new(p).exists())
            .collect();

        if existing_paths.is_empty() {
            debug!(
                device = %device_name,
                "No device paths found for accelerator"
            );
            return None;
        }

        Some(GpuDevice {
            name: device_name,
            family,
            device_id,
            device_paths: existing_paths,
            memory_bytes: profile.memory_bytes,
            driver_version: profile.driver_version.clone(),
        })
    }

    /// Generate Landlock filesystem rules for this device's paths.
    ///
    /// All device paths get read-write access (required for GPU compute).
    #[must_use]
    pub fn to_landlock_rules(&self) -> Vec<LandlockRule> {
        self.device_paths
            .iter()
            .map(|path| LandlockRule {
                path: path.clone(),
                access: "rw".to_string(),
            })
            .collect()
    }

    /// Check if the driver version meets a minimum requirement.
    #[must_use]
    pub fn driver_version_at_least(&self, min_version: &str) -> bool {
        match &self.driver_version {
            Some(v) => v.as_str() >= min_version,
            None => false,
        }
    }
}

/// Collection of GPU devices available for sandbox passthrough.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GpuPassthrough {
    /// Available devices with computed device paths.
    pub devices: Vec<GpuDevice>,
}

impl GpuPassthrough {
    /// Detect all accelerators and compute passthrough device paths.
    ///
    /// Calls `ai_hwaccel::AcceleratorRegistry::detect()` and maps each
    /// detected accelerator to its device node paths.
    #[must_use]
    pub fn detect_all() -> Self {
        let registry = ai_hwaccel::AcceleratorRegistry::builder().detect();
        let mut devices = Vec::new();

        for profile in registry.all_profiles() {
            if !profile.available {
                continue;
            }
            if let Some(device) = GpuDevice::from_accelerator(&profile.accelerator, profile) {
                info!(
                    device = %device.name,
                    paths = ?device.device_paths,
                    memory_mb = device.memory_bytes / (1024 * 1024),
                    "GPU device available for passthrough"
                );
                devices.push(device);
            }
        }

        Self { devices }
    }

    /// Filter devices that satisfy an accelerator requirement.
    #[must_use]
    pub fn matching(&self, requirement: &ai_hwaccel::AcceleratorRequirement) -> Vec<&GpuDevice> {
        self.devices
            .iter()
            .filter(|d| {
                // Map GpuDevice back to a minimal AcceleratorProfile for matching
                let fake_profile = ai_hwaccel::AcceleratorProfile {
                    available: true,
                    memory_bytes: d.memory_bytes,
                    ..Default::default()
                };
                requirement.satisfied_by(&fake_profile)
                    || matches!(
                        (requirement, d.family),
                        (
                            ai_hwaccel::AcceleratorRequirement::Gpu,
                            DeviceFamily::NvidiaGpu
                        ) | (
                            ai_hwaccel::AcceleratorRequirement::Gpu,
                            DeviceFamily::AmdGpu
                        ) | (
                            ai_hwaccel::AcceleratorRequirement::Gpu,
                            DeviceFamily::IntelGpu
                        ) | (ai_hwaccel::AcceleratorRequirement::AnyAccelerator, _)
                    )
            })
            .collect()
    }

    /// Generate combined Landlock rules for all devices.
    #[must_use]
    pub fn to_landlock_rules(&self) -> Vec<LandlockRule> {
        self.devices
            .iter()
            .flat_map(|d| d.to_landlock_rules())
            .collect()
    }

    /// Generate Landlock rules for a specific device by index.
    #[must_use]
    pub fn device_landlock_rules(&self, device_id: u32) -> Vec<LandlockRule> {
        self.devices
            .iter()
            .filter(|d| d.device_id == device_id)
            .flat_map(|d| d.to_landlock_rules())
            .collect()
    }
}

/// Policy for GPU access within sandboxes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct GpuPolicy {
    /// Whether GPU access is allowed.
    pub enabled: bool,
    /// Maximum VRAM in MB (0 = no limit).
    pub max_vram_mb: u64,
    /// Allowed device families (empty = allow all).
    pub allowed_families: Vec<DeviceFamily>,
    /// Minimum driver version required (per-family).
    pub min_driver_version: Option<String>,
    /// Maximum number of devices to expose (0 = no limit).
    pub max_devices: u32,
}

impl GpuPolicy {
    /// Allow all GPUs with no restrictions.
    #[must_use]
    pub fn allow_all() -> Self {
        Self {
            enabled: true,
            ..Default::default()
        }
    }

    /// Allow only NVIDIA GPUs.
    #[must_use]
    pub fn nvidia_only() -> Self {
        Self {
            enabled: true,
            allowed_families: vec![DeviceFamily::NvidiaGpu],
            ..Default::default()
        }
    }

    /// Check if a device is allowed by this policy.
    #[must_use]
    pub fn allows_device(&self, device: &GpuDevice) -> bool {
        if !self.enabled {
            return false;
        }
        if !self.allowed_families.is_empty() && !self.allowed_families.contains(&device.family) {
            return false;
        }
        if self.max_vram_mb > 0 && device.memory_bytes / (1024 * 1024) > self.max_vram_mb {
            return false;
        }
        if let Some(ref min_ver) = self.min_driver_version
            && !device.driver_version_at_least(min_ver)
        {
            warn!(
                device = %device.name,
                min = %min_ver,
                actual = ?device.driver_version,
                "GPU driver version below minimum"
            );
            return false;
        }
        true
    }

    /// Filter a passthrough list to only policy-allowed devices, respecting max_devices.
    #[must_use]
    pub fn filter<'a>(&self, passthrough: &'a GpuPassthrough) -> Vec<&'a GpuDevice> {
        let mut allowed: Vec<&GpuDevice> = passthrough
            .devices
            .iter()
            .filter(|d| self.allows_device(d))
            .collect();
        if self.max_devices > 0 {
            allowed.truncate(self.max_devices as usize);
        }
        allowed
    }
}

/// Enumerate DRI render nodes for a device.
///
/// Scans `/dev/dri/renderD*` for the render node corresponding to `device_id`.
/// On Linux, render nodes start at 128 (renderD128 = card0, renderD129 = card1, etc.).
fn enumerate_dri_render_nodes(device_id: u32) -> Vec<String> {
    let render_node = format!("/dev/dri/renderD{}", 128 + device_id);
    let card_node = format!("/dev/dri/card{device_id}");
    let mut paths = Vec::with_capacity(2);
    if std::path::Path::new(&render_node).exists() {
        paths.push(render_node);
    }
    if std::path::Path::new(&card_node).exists() {
        paths.push(card_node);
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_family_variants() {
        assert_ne!(DeviceFamily::NvidiaGpu, DeviceFamily::AmdGpu);
        assert_ne!(DeviceFamily::GoogleTpu, DeviceFamily::AwsNeuron);
    }

    #[test]
    fn gpu_device_landlock_rules() {
        let device = GpuDevice {
            name: "Test GPU".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec!["/dev/nvidia0".into(), "/dev/nvidiactl".into()],
            memory_bytes: 24 * 1024 * 1024 * 1024,
            driver_version: Some("550.54".into()),
        };
        let rules = device.to_landlock_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.access == "rw"));
        assert!(rules.iter().any(|r| r.path == "/dev/nvidia0"));
    }

    #[test]
    fn driver_version_check() {
        let device = GpuDevice {
            name: "Test".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: Some("550.54".into()),
        };
        assert!(device.driver_version_at_least("535"));
        assert!(device.driver_version_at_least("550"));
        assert!(!device.driver_version_at_least("560"));
    }

    #[test]
    fn driver_version_missing() {
        let device = GpuDevice {
            name: "Test".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: None,
        };
        assert!(!device.driver_version_at_least("535"));
    }

    #[test]
    fn gpu_policy_disabled() {
        let policy = GpuPolicy::default();
        let device = GpuDevice {
            name: "GPU".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: None,
        };
        assert!(!policy.allows_device(&device));
    }

    #[test]
    fn gpu_policy_allow_all() {
        let policy = GpuPolicy::allow_all();
        let device = GpuDevice {
            name: "GPU".into(),
            family: DeviceFamily::AmdGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: None,
        };
        assert!(policy.allows_device(&device));
    }

    #[test]
    fn gpu_policy_nvidia_only() {
        let policy = GpuPolicy::nvidia_only();
        let nvidia = GpuDevice {
            name: "RTX".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: None,
        };
        let amd = GpuDevice {
            name: "Radeon".into(),
            family: DeviceFamily::AmdGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: None,
        };
        assert!(policy.allows_device(&nvidia));
        assert!(!policy.allows_device(&amd));
    }

    #[test]
    fn gpu_policy_max_devices() {
        let policy = GpuPolicy {
            enabled: true,
            max_devices: 1,
            ..Default::default()
        };
        let passthrough = GpuPassthrough {
            devices: vec![
                GpuDevice {
                    name: "GPU0".into(),
                    family: DeviceFamily::NvidiaGpu,
                    device_id: 0,
                    device_paths: vec![],
                    memory_bytes: 0,
                    driver_version: None,
                },
                GpuDevice {
                    name: "GPU1".into(),
                    family: DeviceFamily::NvidiaGpu,
                    device_id: 1,
                    device_paths: vec![],
                    memory_bytes: 0,
                    driver_version: None,
                },
            ],
        };
        let filtered = policy.filter(&passthrough);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn gpu_policy_min_driver() {
        let policy = GpuPolicy {
            enabled: true,
            min_driver_version: Some("550".into()),
            ..Default::default()
        };
        let good = GpuDevice {
            name: "GPU".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: Some("560".into()),
        };
        let bad = GpuDevice {
            name: "GPU".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec![],
            memory_bytes: 0,
            driver_version: Some("535".into()),
        };
        assert!(policy.allows_device(&good));
        assert!(!policy.allows_device(&bad));
    }

    #[test]
    fn passthrough_empty() {
        let pt = GpuPassthrough::default();
        assert!(pt.devices.is_empty());
        assert!(pt.to_landlock_rules().is_empty());
    }

    #[test]
    fn passthrough_combined_rules() {
        let pt = GpuPassthrough {
            devices: vec![
                GpuDevice {
                    name: "GPU0".into(),
                    family: DeviceFamily::NvidiaGpu,
                    device_id: 0,
                    device_paths: vec!["/dev/nvidia0".into()],
                    memory_bytes: 0,
                    driver_version: None,
                },
                GpuDevice {
                    name: "GPU1".into(),
                    family: DeviceFamily::NvidiaGpu,
                    device_id: 1,
                    device_paths: vec!["/dev/nvidia1".into()],
                    memory_bytes: 0,
                    driver_version: None,
                },
            ],
        };
        let rules = pt.to_landlock_rules();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn gpu_device_serde() {
        let device = GpuDevice {
            name: "Test".into(),
            family: DeviceFamily::NvidiaGpu,
            device_id: 0,
            device_paths: vec!["/dev/nvidia0".into()],
            memory_bytes: 24_000_000_000,
            driver_version: Some("550".into()),
        };
        let json = serde_json::to_string(&device).unwrap();
        let back: GpuDevice = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test");
        assert_eq!(back.device_paths.len(), 1);
    }

    #[test]
    fn gpu_policy_serde() {
        let policy = GpuPolicy::nvidia_only();
        let json = serde_json::to_string(&policy).unwrap();
        let back: GpuPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.enabled);
        assert_eq!(back.allowed_families, vec![DeviceFamily::NvidiaGpu]);
    }
}
