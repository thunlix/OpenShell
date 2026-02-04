//! gRPC client for fetching sandbox policy from Navigator server.

use miette::{IntoDiagnostic, Result};
use navigator_core::proto::{
    GetSandboxPolicyRequest, SandboxPolicy as ProtoSandboxPolicy, navigator_client::NavigatorClient,
};
use tracing::debug;

/// Fetch sandbox policy from Navigator server via gRPC.
///
/// # Arguments
///
/// * `endpoint` - The Navigator server gRPC endpoint (e.g., `http://navigator:8080`)
/// * `sandbox_id` - The sandbox ID to fetch policy for
///
/// # Errors
///
/// Returns an error if the gRPC connection fails or the sandbox is not found.
pub async fn fetch_policy(endpoint: &str, sandbox_id: &str) -> Result<ProtoSandboxPolicy> {
    debug!(endpoint = %endpoint, sandbox_id = %sandbox_id, "Connecting to Navigator server");

    let mut client = NavigatorClient::connect(endpoint.to_string())
        .await
        .into_diagnostic()?;

    debug!("Connected, fetching sandbox policy");

    let response = client
        .get_sandbox_policy(GetSandboxPolicyRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?;

    response
        .into_inner()
        .policy
        .ok_or_else(|| miette::miette!("Server returned empty policy"))
}
