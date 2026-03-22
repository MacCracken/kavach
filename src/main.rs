use clap::{Parser, Subcommand};
use kavach::{Backend, Sandbox, SandboxConfig, SandboxPolicy, SandboxState, score_backend};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "kavach", version, about = "Sandbox execution framework")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Execute a command inside a sandbox
    Exec {
        /// Backend to use
        #[arg(short, long, default_value = "process")]
        backend: String,

        /// Security policy: minimal, basic, strict
        #[arg(short, long, default_value = "basic")]
        policy: String,

        /// Disable network access
        #[arg(long)]
        no_network: bool,

        /// Timeout in milliseconds
        #[arg(short, long, default_value_t = 30_000)]
        timeout: u64,

        /// Command to run
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// List available sandbox backends
    Backends,

    /// Score the security strength of a backend + policy combination
    Score {
        /// Backend to score
        #[arg(short, long, default_value = "process")]
        backend: String,

        /// Security policy: minimal, basic, strict
        #[arg(short, long, default_value = "basic")]
        policy: String,

        /// Disable network in scoring
        #[arg(long)]
        no_network: bool,
    },
}

fn parse_backend(s: &str) -> Result<Backend, String> {
    match s.to_lowercase().as_str() {
        "process" => Ok(Backend::Process),
        "gvisor" => Ok(Backend::GVisor),
        "firecracker" => Ok(Backend::Firecracker),
        "wasm" => Ok(Backend::Wasm),
        "oci" => Ok(Backend::Oci),
        "sgx" => Ok(Backend::Sgx),
        "sev" => Ok(Backend::Sev),
        "sy-agnos" | "syagnos" => Ok(Backend::SyAgnos),
        "noop" => Ok(Backend::Noop),
        other => Err(format!("unknown backend: {other}")),
    }
}

fn parse_policy(s: &str, no_network: bool) -> Result<SandboxPolicy, String> {
    let mut policy = match s.to_lowercase().as_str() {
        "minimal" => SandboxPolicy::minimal(),
        "basic" => SandboxPolicy::basic(),
        "strict" => SandboxPolicy::strict(),
        other => {
            return Err(format!(
                "unknown policy: {other} (use minimal, basic, strict)"
            ));
        }
    };
    if no_network {
        policy.network.enabled = false;
    }
    Ok(policy)
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Exec {
            backend,
            policy,
            no_network,
            timeout,
            cmd,
        } => {
            let backend = match parse_backend(&backend) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let policy = match parse_policy(&policy, no_network) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };

            let config = SandboxConfig::builder()
                .backend(backend)
                .policy(policy)
                .timeout_ms(timeout)
                .build();

            let mut sandbox = match Sandbox::create(config).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error creating sandbox: {e}");
                    return ExitCode::from(1);
                }
            };

            if let Err(e) = sandbox.transition(SandboxState::Running) {
                eprintln!("error starting sandbox: {e}");
                return ExitCode::from(1);
            }

            let command = cmd.join(" ");
            let result = match sandbox.exec(&command).await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("error executing command: {e}");
                    let _ = sandbox.destroy().await;
                    return ExitCode::from(1);
                }
            };

            if !result.stdout.is_empty() {
                print!("{}", result.stdout);
            }
            if !result.stderr.is_empty() {
                eprint!("{}", result.stderr);
            }

            let _ = sandbox.destroy().await;

            if result.timed_out {
                ExitCode::from(124)
            } else {
                ExitCode::from(result.exit_code as u8)
            }
        }

        Command::Backends => {
            println!("{:<15} AVAILABLE", "BACKEND");
            for b in Backend::all() {
                let available = if b.is_available() { "yes" } else { "no" };
                println!("{:<15} {}", b, available);
            }
            ExitCode::SUCCESS
        }

        Command::Score {
            backend,
            policy,
            no_network,
        } => {
            let backend = match parse_backend(&backend) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };
            let policy = match parse_policy(&policy, no_network) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::from(2);
                }
            };

            let score = score_backend(backend, &policy);
            println!("{score}");
            ExitCode::SUCCESS
        }
    }
}
