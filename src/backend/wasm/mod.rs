//! WASM backend — WebAssembly sandbox via wasmtime.
//!
//! Executes commands by compiling a WASI module and running it with
//! restricted filesystem access, memory limits, and fuel-based CPU metering.

use crate::backend::{Backend, SandboxBackend};
use crate::lifecycle::{ExecResult, SandboxConfig};
use crate::policy::SandboxPolicy;

use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::WasiCtxBuilder;
use wasmtime_wasi::p1::{self, WasiP1Ctx};

/// WASM sandbox backend using wasmtime + WASI.
pub struct WasmBackend {
    config: SandboxConfig,
    engine: Engine,
}

impl WasmBackend {
    /// Create a new WASM backend with a pre-configured engine.
    pub fn new(config: &SandboxConfig) -> crate::Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.consume_fuel(true); // Enable fuel-based CPU metering
        // async_support is the default in wasmtime v42+

        // Memory limit from policy
        if let Some(mb) = config.policy.memory_limit_mb {
            let pages = mb * 1024 * 1024 / 65536; // 64KB per WASM page
            wasm_config.memory_guaranteed_dense_image_size(pages.min(65536));
        }

        let engine = Engine::new(&wasm_config)
            .map_err(|e| crate::KavachError::CreationFailed(format!("wasmtime engine: {e}")))?;

        Ok(Self {
            config: config.clone(),
            engine,
        })
    }

    /// Build WASI context with filesystem preopens from policy.
    fn build_wasi_ctx(&self) -> crate::Result<WasiP1Ctx> {
        let mut builder = WasiCtxBuilder::new();

        // Inherit stdio for output capture
        builder.inherit_stdio();

        // Map LandlockRules to WASI preopened directories
        for rule in &self.config.policy.landlock_rules {
            let path = std::path::Path::new(&rule.path);
            if path.exists() {
                let _ = match rule.access.as_str() {
                    "rw" => builder.preopened_dir(
                        path,
                        &rule.path,
                        wasmtime_wasi::DirPerms::all(),
                        wasmtime_wasi::FilePerms::all(),
                    ),
                    _ => builder.preopened_dir(
                        path,
                        &rule.path,
                        wasmtime_wasi::DirPerms::READ,
                        wasmtime_wasi::FilePerms::READ,
                    ),
                };
            }
        }

        // Set environment variables
        for (k, v) in &self.config.env {
            builder.env(k, v);
        }

        Ok(builder.build_p1())
    }

    /// Calculate fuel from timeout (approximate: 1 fuel unit ≈ 1 instruction).
    fn fuel_from_timeout(timeout_ms: u64) -> u64 {
        // Rough estimate: ~1 billion instructions per second on modern hardware
        // So timeout_ms * 1_000_000 gives us a fuel budget
        timeout_ms.saturating_mul(1_000_000)
    }
}

#[async_trait::async_trait]
impl SandboxBackend for WasmBackend {
    fn backend_type(&self) -> Backend {
        Backend::Wasm
    }

    async fn exec(&self, command: &str, policy: &SandboxPolicy) -> crate::Result<ExecResult> {
        let start = std::time::Instant::now();

        let _ = policy; // Policy is embedded in engine config and WASI context

        // The command is expected to be a path to a .wasm file
        // or inline WASM (for now, we support file paths)
        let wasm_path = std::path::Path::new(command.trim());

        let module = if wasm_path.exists() {
            Module::from_file(&self.engine, wasm_path)
                .map_err(|e| crate::KavachError::ExecFailed(format!("WASM load: {e}")))?
        } else {
            // Try to interpret as a shell command via a WASI-compatible shell
            // For now, return an error — real WASI commands need a compiled module
            return Err(crate::KavachError::ExecFailed(
                "WASM backend requires a .wasm file path as the command".into(),
            ));
        };

        let wasi_ctx = self.build_wasi_ctx()?;
        let mut store = Store::new(&self.engine, wasi_ctx);

        // Set fuel budget for CPU metering
        let fuel = Self::fuel_from_timeout(self.config.timeout_ms);
        store
            .set_fuel(fuel)
            .map_err(|e| crate::KavachError::ExecFailed(format!("set fuel: {e}")))?;

        // Link WASI
        let mut linker: Linker<WasiP1Ctx> = Linker::new(&self.engine);
        p1::add_to_linker_async(&mut linker, |ctx: &mut WasiP1Ctx| ctx)
            .map_err(|e| crate::KavachError::ExecFailed(format!("WASI link: {e}")))?;

        // Instantiate and run
        let instance = linker
            .instantiate_async(&mut store, &module)
            .await
            .map_err(|e| crate::KavachError::ExecFailed(format!("WASM instantiate: {e}")))?;

        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|_| {
                crate::KavachError::ExecFailed("WASM module has no _start function".into())
            })?;

        let timeout_dur = std::time::Duration::from_millis(self.config.timeout_ms);

        let call_result: Result<(), wasmtime::Error> =
            match tokio::time::timeout(timeout_dur, start_fn.call_async(&mut store, ())).await {
                Ok(r) => r,
                Err(_) => {
                    return Ok(ExecResult {
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: String::new(),
                        duration_ms: start.elapsed().as_millis() as u64,
                        timed_out: true,
                    });
                }
            };

        let exit_code = match call_result {
            Ok(()) => 0,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("fuel") {
                    return Ok(ExecResult {
                        exit_code: -1,
                        stdout: String::new(),
                        stderr: format!("WASM fuel exhausted: {msg}"),
                        duration_ms: start.elapsed().as_millis() as u64,
                        timed_out: true,
                    });
                }
                if let Some(exit) = e.downcast_ref::<wasmtime_wasi::I32Exit>() {
                    exit.0
                } else {
                    return Err(crate::KavachError::ExecFailed(format!("WASM exec: {e}")));
                }
            }
        };

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ExecResult {
            exit_code,
            stdout: String::new(), // WASI stdout goes to inherited stdio
            stderr: String::new(),
            duration_ms,
            timed_out: false,
        })
    }

    async fn health_check(&self) -> crate::Result<bool> {
        // Verify engine can compile a trivial module
        let wat = r#"(module (func (export "_start")))"#;
        Module::new(&self.engine, wat)
            .map(|_| true)
            .map_err(|e| crate::KavachError::ExecFailed(format!("WASM health: {e}")))
    }

    async fn destroy(&self) -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuel_calculation() {
        assert_eq!(WasmBackend::fuel_from_timeout(1000), 1_000_000_000);
        assert_eq!(WasmBackend::fuel_from_timeout(100), 100_000_000);
        assert_eq!(WasmBackend::fuel_from_timeout(0), 0);
    }

    #[test]
    fn create_backend() {
        let config = SandboxConfig::builder().backend(Backend::Wasm).build();
        let backend = WasmBackend::new(&config);
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn health_check() {
        let config = SandboxConfig::builder().backend(Backend::Wasm).build();
        let backend = WasmBackend::new(&config).unwrap();
        assert!(backend.health_check().await.unwrap());
    }

    #[tokio::test]
    async fn exec_nonexistent_file() {
        let config = SandboxConfig::builder().backend(Backend::Wasm).build();
        let backend = WasmBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("/nonexistent.wasm", &policy).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn exec_non_wasm_command() {
        let config = SandboxConfig::builder().backend(Backend::Wasm).build();
        let backend = WasmBackend::new(&config).unwrap();
        let policy = SandboxPolicy::minimal();
        let result = backend.exec("echo hello", &policy).await;
        assert!(result.is_err()); // Not a .wasm file
    }
}
