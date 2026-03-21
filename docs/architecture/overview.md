# Kavach Architecture

> Sandbox execution framework — backend abstraction, strength scoring, policy engine,
> credential proxy, and audit hooks.
>
> **Name**: Kavach (कवच, Sanskrit) — armor, shield. Protects both what's inside and what's outside.
> Extracted from [SecureYeoman](https://github.com/MacCracken/SecureYeoman)'s production sandbox framework.

---

## Design Principles

1. **Backend-agnostic** — same API whether you're using process isolation, gVisor, Firecracker, WASM, or hardware enclaves
2. **Quantitative security** — every sandbox gets a numeric strength score (0–100), not a vague "secure/insecure"
3. **Secrets never touch disk** — credential proxy injects via env/pipe, sandbox process never sees the filesystem path
4. **Externalization gate** — nothing leaves the sandbox without passing the policy check
5. **Audit by default** — every lifecycle event (create, exec, stop, destroy) is loggable

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Consumers (SY, daimon, AgnosAI, aethersafta)                │
│                                                              │
│  Sandbox::create(config) → exec("command") → destroy()       │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  Kavach Core                                                 │
│                                                              │
│  ┌─────────┐  ┌──────────┐  ┌────────────┐  ┌───────────┐ │
│  │ Policy  │  │ Scoring  │  │ Credential │  │ Lifecycle │ │
│  │ Engine  │  │ (0-100)  │  │   Proxy    │  │   FSM     │ │
│  └────┬────┘  └────┬─────┘  └─────┬──────┘  └─────┬─────┘ │
│       └────────────┴──────────────┴────────────────┘        │
│                           │                                  │
│  ┌────────────────────────▼────────────────────────────────┐│
│  │              Backend Dispatch                            ││
│  │  ┌─────────┐ ┌────────┐ ┌──────┐ ┌────┐ ┌───┐ ┌───┐  ││
│  │  │ Process │ │ gVisor │ │ WASM │ │ OCI│ │SGX│ │SEV│  ││
│  │  │ (50)    │ │ (70)   │ │ (65) │ │(55)│ │(80│ │(82│  ││
│  │  └─────────┘ └────────┘ └──────┘ └────┘ └───┘ └───┘  ││
│  │  ┌─────────────┐ ┌──────┐                              ││
│  │  │ Firecracker │ │ Noop │                              ││
│  │  │ (90)        │ │ (0)  │                              ││
│  │  └─────────────┘ └──────┘                              ││
│  └─────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

---

## Module Structure

```
src/
├── lib.rs              Public API, Result type
├── error.rs            KavachError enum
├── backend/
│   └── mod.rs          Backend enum, SandboxBackend trait, availability detection
├── scoring/
│   └── mod.rs          StrengthScore (0-100), base_score(), score_backend()
├── policy/
│   └── mod.rs          SandboxPolicy, SeccompProfile, LandlockRule, NetworkPolicy
├── credential/
│   └── mod.rs          CredentialProxy, SecretRef, InjectionMethod
├── lifecycle/
│   └── mod.rs          Sandbox, SandboxConfig, SandboxState FSM, ExecResult
└── tests/
    └── mod.rs          Integration tests
```

---

## Strength Scoring

| Backend | Base Score | Label |
|---------|-----------|-------|
| Noop | 0 | minimal |
| Process | 50 | standard |
| OCI | 55 | standard |
| WASM | 65 | standard |
| gVisor | 70 | hardened |
| SGX | 80 | hardened |
| SEV | 82 | hardened |
| Firecracker | 90 | fortress |

Policy modifiers:
- +5 for seccomp enabled
- +3 for Landlock rules
- +5 for network disabled
- +3 for read-only rootfs
- +2 for resource limits

Maximum achievable: Firecracker + all modifiers = 100 (fortress).

---

## Consumers

| Project | Usage |
|---------|-------|
| **SecureYeoman** | Drops internal sandbox framework, adopts kavach for all agent execution |
| **daimon** | Replaces 7 internal sandbox backends with kavach's unified trait |
| **AgnosAI** | Sandboxed crew execution (WASM/OCI agents) |
| **aethersafta** | Sandboxed plugin execution for compositor extensions |
| **sutra** | Sandboxed remote command execution on fleet nodes |
