# Server Architecture

## Overview

`navigator-server` is the gateway service that exposes gRPC APIs, HTTP health endpoints, and
optional TLS on a single shared port. It also persists sandbox data and coordinates Kubernetes
sandbox lifecycle.

## Components

- **Entry point**: `crates/navigator-server/src/main.rs`
  - Loads config, sets up tracing, and invokes `run_server`.
- **Server runtime**: `crates/navigator-server/src/lib.rs`
  - Builds shared `ServerState`, starts background watchers, and accepts connections.
- **Protocol multiplexing**: `crates/navigator-server/src/multiplex.rs`
  - Routes requests by inspecting `content-type`.
  - `application/grpc*` goes to gRPC handlers; everything else to HTTP router.
- **gRPC API**: `crates/navigator-server/src/grpc.rs`
  - Implements `Navigator` service (health, sandbox CRUD, watch streaming).
- **HTTP API**: `crates/navigator-server/src/http.rs`
  - Simple health endpoints: `/health`, `/healthz`, `/readyz`.
- **TLS**: `crates/navigator-server/src/tls.rs`
  - Wraps accepted connections with rustls when TLS is configured.
  - ALPN advertises `h2` and `http/1.1` so gRPC and HTTP can share the port.
- **Persistence**: `crates/navigator-server/src/persistence/`
  - Stores protobuf messages in SQLite or Postgres.
  - Selected by database URL.
- **Sandbox integration**: `crates/navigator-server/src/sandbox/`
  - Creates sandbox CRDs in Kubernetes and watches for status updates.
- **Event and log buses**: `crates/navigator-server/src/sandbox_watch.rs`,
  `crates/navigator-server/src/tracing_bus.rs`
  - In-memory buses used to stream sandbox updates and logs over gRPC.

## Connection Flow

1. TCP listener accepts a connection (TLS optional).
2. If TLS is enabled, the connection is upgraded with rustls.
3. The multiplexing layer inspects each request:
   - `content-type: application/grpc` -> gRPC service
   - otherwise -> HTTP router

## Multiplexing Details

The multiplexing implementation is in `crates/navigator-server/src/multiplex.rs` and uses
Hyper’s per-connection server with a custom service:

- Each accepted connection is handed to Hyper’s `server::conn::auto::Builder`, which handles
  HTTP/1.1 and HTTP/2 on the same socket.
- A lightweight `MultiplexedService` implements `hyper::service::Service<Request<Incoming>>`.
- For each request, the service checks the request headers and routes based on:
  - `content-type` header starts with `application/grpc` -> gRPC handler
  - otherwise -> HTTP health router
- Both the gRPC and HTTP handlers are `tower::Service` implementations. Requests are converted
  into a boxed body type (`BoxBody`) to normalize differences between the two stacks, then the
  response is boxed back for Hyper.

### TLS + ALPN Interaction

When TLS is enabled:

- `TlsAcceptor` wraps the incoming TCP stream before it reaches Hyper.
- ALPN advertises `h2` and `http/1.1`, which lets:
  - gRPC clients negotiate HTTP/2 automatically
  - health checks fall back to HTTP/1.1 if needed

### Routing Assumptions

- gRPC detection is header-based and assumes well-formed gRPC requests include
  `content-type: application/grpc` (including variants like `application/grpc+proto`).
- Non-gRPC traffic (including HTTP health checks) is routed to the HTTP router.

## Notes

- gRPC and HTTP share the same bind address and port.
- TLS requires ALPN to negotiate `h2` for gRPC and `http/1.1` for health checks.
