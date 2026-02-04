# Sandbox Architecture

Navigator's sandboxing isolates a user command in a child process while policy parsing and
platform-specific enforcement live behind clear interfaces. The `navigator-sandbox` binary is the
entry point and spawns a child process, applying restrictions before `exec`.

## Components

- `crates/navigator-sandbox`: CLI + library that loads policy, spawns the child process, and applies sandbox rules.
- `crates/navigator-core`: shared types and utilities (policy schema, errors, config).
- `crates/navigator-server`: Server that stores sandbox policies and serves them via gRPC.

## Policy Model

Sandboxing is driven by a required policy configuration. There are two ways to provide it:

1. **gRPC mode** (production): Set `NAVIGATOR_SANDBOX_ID` and `NAVIGATOR_ENDPOINT` environment
   variables. The sandbox will fetch its policy from the Navigator server at startup via the
   `GetSandboxPolicy` RPC.

2. **File mode** (local development): Provide a YAML policy file via `--policy` or
   `NAVIGATOR_SANDBOX_POLICY`.

The policy schema includes:

- `filesystem`: read-only and read-write allow lists, plus optional inclusion of the workdir.
- `network`: mode (`allow`, `block`, `proxy`) and optional proxy configuration.
- `landlock`: compatibility behavior (`best_effort` or `hard_requirement`).
- `process`: optional `run_as_user`/`run_as_group` to drop privileges for the child process.

See `docs/sandbox-policy.yaml` for an example policy.

## Dynamic Policy Loading (gRPC Mode)

When running in Kubernetes, the sandbox fetches its policy dynamically from the Navigator server
via gRPC instead of reading from a local file. This is the preferred mode for production deployments.

### Environment Variables

The pod template automatically injects these environment variables:

- `NAVIGATOR_SANDBOX_ID`: The sandbox entity ID in Navigator's store
- `NAVIGATOR_ENDPOINT`: gRPC endpoint for the Navigator server (e.g., `http://navigator:8080`)
- `NAVIGATOR_SANDBOX_COMMAND`: The command to execute inside the sandbox (user-provided, defaults to `/bin/bash` if not set)

### Startup Flow

1. Pod starts with `navigator-sandbox` entrypoint
2. Sandbox binary reads `NAVIGATOR_SANDBOX_ID` and `NAVIGATOR_ENDPOINT` from environment
3. Calls `GetSandboxPolicy(sandbox_id)` gRPC to fetch policy from Navigator server
4. Applies sandbox restrictions (Landlock, seccomp, privilege drop)
5. Executes the command from `NAVIGATOR_SANDBOX_COMMAND`, CLI args, or `/bin/bash` by default

### Policy Storage

The sandbox policy is stored as part of the `SandboxSpec` protobuf message in Navigator's persistence
layer. The policy is required when creating a sandbox via the `CreateSandbox` gRPC call. The policy
definition lives in `proto/sandbox.proto`.

## Linux Enforcement (Landlock + Seccomp)

Linux enforcement lives in `crates/navigator-sandbox/src/sandbox/linux`.

- Landlock restricts filesystem access to the allow lists from the policy. If no paths are listed,
  Landlock is skipped. When enabled, a ruleset is created and enforced before the child `exec`.
- Seccomp blocks socket creation for common network domains (IPv4/IPv6 and others), preventing the
  child process from opening outbound sockets directly.

## Proxy Routing

When `network.mode: proxy` is set, `NAVIGATOR_PROXY_SOCKET` is exported to the child. Seccomp still
blocks direct socket creation so traffic must flow through the proxy channel.

## Process Privileges

The sandbox supervisor can run as a more privileged user while the child process drops to a less
privileged account before `exec`. Configure this via `process.run_as_user` and
`process.run_as_group` in the policy. If unset, the child inherits the supervisor's user/group.

## Platform Extensibility

Platform-specific implementations are wired through `crates/navigator-sandbox/src/sandbox/mod.rs`.
Non-Linux platforms currently log a warning and skip enforcement, leaving room for a macOS backend
later without changing the public policy or CLI surface.
