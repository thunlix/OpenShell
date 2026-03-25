// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tether bridge — connects the OpenShell sandbox supervisor to a Tether server.
//!
//! The bridge translates proxy telemetry (allowed connections, denials) into
//! Tether activity reports and executes enforcement verdicts (continue, caution,
//! halt) by tightening sandbox policy or terminating the process.
//!
//! ## Trust model
//!
//! The bridge reports ground-truth observations from the proxy — the agent
//! never self-reports. Tether scores drift against the agent's committed intent
//! and returns a verdict that the bridge executes.
//!
//! ## Failure behaviour
//!
//! If Tether is unreachable, the bridge logs a warning and continues with the
//! last-known verdict. No new permissions are granted. The sandbox does not
//! crash because Tether is down.

use crate::activity_aggregator::FlushableActivitySummary;
use crate::denial_aggregator::FlushableDenialSummary;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Configuration for the Tether bridge, parsed from sandbox policy.
#[derive(Debug, Clone)]
pub struct TetherConfig {
    /// Tether server base URL (e.g. "http://tether:3000").
    pub endpoint: String,
    /// Task ID in Tether that this sandbox is reporting against.
    pub task_id: String,
    /// Enforcement mode: "enforce" (act on verdicts) or "monitor" (log only).
    pub mode: TetherMode,
    /// HTTP request timeout.
    pub timeout: Duration,
}

/// Enforcement mode for the Tether bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TetherMode {
    /// Act on verdicts: tighten policy on caution, terminate on halt.
    Enforce,
    /// Log verdicts but take no enforcement action.
    Monitor,
}

/// Verdict returned by Tether after scoring activity drift.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TetherVerdict {
    /// "continue", "caution", or "halt".
    pub verdict: String,
    /// Drift score (0.0 = aligned, 1.0 = completely drifted).
    pub drift_score: Option<f64>,
    /// Human-readable feedback.
    pub feedback: Option<String>,
    /// Number of actions logged in this report.
    pub actions_logged: Option<u32>,
    /// Block index in the Tether chain.
    pub chain_block_index: Option<u64>,
}

/// Request body for POST /api/activity/report.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityReportRequest {
    task_id: String,
    reported_by: String,
    activities: Vec<ActivityRecord>,
    denials: Vec<DenialRecord>,
}

/// A single activity record sent to Tether.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityRecord {
    host: String,
    port: u16,
    binary: String,
    matched_policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    count: u32,
}

/// A single denial record sent to Tether.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DenialRecord {
    host: String,
    port: u16,
    binary: String,
    reason: String,
    count: u32,
}

/// Action to take after evaluating a Tether verdict.
#[derive(Debug, Clone, PartialEq)]
pub enum VerdictAction {
    /// No enforcement action needed.
    Continue,
    /// Tighten the sandbox policy (remove non-essential network rules).
    TightenPolicy {
        /// The drift score that triggered the tightening.
        drift_score: f64,
    },
    /// Terminate the sandbox process.
    Terminate,
}

/// The Tether bridge. Thread-safe, designed to be wrapped in an `Arc`.
pub struct TetherBridge {
    client: reqwest::Client,
    config: TetherConfig,
    /// Last-known verdict — used when Tether is unreachable.
    last_verdict: RwLock<TetherVerdict>,
}

impl TetherBridge {
    /// Create a new bridge with the given configuration.
    pub fn new(config: TetherConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            config,
            last_verdict: RwLock::new(TetherVerdict {
                verdict: "continue".into(),
                drift_score: None,
                feedback: None,
                actions_logged: None,
                chain_block_index: None,
            }),
        }
    }

    /// Report allowed activity to Tether and return the verdict.
    ///
    /// Called by the activity aggregator flush callback.
    pub async fn report_activity(
        &self,
        summaries: &[FlushableActivitySummary],
    ) -> TetherVerdict {
        let activities: Vec<ActivityRecord> = summaries
            .iter()
            .flat_map(|s| {
                if s.l7_samples.is_empty() {
                    // L4-only: one record per summary
                    vec![ActivityRecord {
                        host: s.host.clone(),
                        port: s.port,
                        binary: s.binary.clone(),
                        matched_policy: s.matched_policy.clone(),
                        method: None,
                        path: None,
                        count: s.count,
                    }]
                } else {
                    // L7: one record per method+path sample
                    s.l7_samples
                        .iter()
                        .map(|l7| ActivityRecord {
                            host: s.host.clone(),
                            port: s.port,
                            binary: s.binary.clone(),
                            matched_policy: s.matched_policy.clone(),
                            method: Some(l7.method.clone()),
                            path: Some(l7.path.clone()),
                            count: l7.count,
                        })
                        .collect()
                }
            })
            .collect();

        self.send_report(activities, Vec::new()).await
    }

    /// Report denials to Tether and return the verdict.
    ///
    /// Called by the denial aggregator flush callback.
    pub async fn report_denials(
        &self,
        summaries: &[FlushableDenialSummary],
    ) -> TetherVerdict {
        let denials: Vec<DenialRecord> = summaries
            .iter()
            .map(|s| DenialRecord {
                host: s.host.clone(),
                port: s.port,
                binary: s.binary.clone(),
                reason: s.deny_reason.clone(),
                count: s.count,
            })
            .collect();

        self.send_report(Vec::new(), denials).await
    }

    /// Send an activity report to Tether and handle the response.
    async fn send_report(
        &self,
        activities: Vec<ActivityRecord>,
        denials: Vec<DenialRecord>,
    ) -> TetherVerdict {
        let url = format!("{}/api/activity/report", self.config.endpoint);
        let body = ActivityReportRequest {
            task_id: self.config.task_id.clone(),
            reported_by: "openshell-supervisor".into(),
            activities,
            denials,
        };

        match self.client.post(&url).json(&body).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<TetherVerdict>().await {
                        Ok(verdict) => {
                            info!(
                                verdict = %verdict.verdict,
                                drift_score = ?verdict.drift_score,
                                "Tether verdict received"
                            );
                            *self.last_verdict.write().await = verdict.clone();
                            verdict
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to parse Tether response");
                            self.last_verdict.read().await.clone()
                        }
                    }
                } else {
                    warn!(
                        status = %resp.status(),
                        "Tether returned non-success status"
                    );
                    self.last_verdict.read().await.clone()
                }
            }
            Err(e) => {
                warn!(error = %e, "Tether unreachable — using last-known verdict");
                self.last_verdict.read().await.clone()
            }
        }
    }

    /// Poll the current verdict from Tether.
    pub async fn poll_verdict(&self) -> TetherVerdict {
        let url = format!(
            "{}/api/task/{}/verdict",
            self.config.endpoint, self.config.task_id
        );

        match self.client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<TetherVerdict>().await {
                    Ok(verdict) => {
                        *self.last_verdict.write().await = verdict.clone();
                        verdict
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to parse Tether verdict response");
                        self.last_verdict.read().await.clone()
                    }
                }
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Tether verdict poll failed");
                self.last_verdict.read().await.clone()
            }
            Err(e) => {
                warn!(error = %e, "Tether unreachable during verdict poll");
                self.last_verdict.read().await.clone()
            }
        }
    }

    /// Execute a verdict. Returns the enforcement action taken.
    ///
    /// In `Monitor` mode, verdicts are logged but no enforcement action is taken.
    /// In `Enforce` mode:
    /// - `continue`: no action
    /// - `caution`: log warning + signal policy tightening
    /// - `halt`: signal sandbox termination
    pub async fn execute_verdict(&self, verdict: &TetherVerdict) -> VerdictAction {
        match self.config.mode {
            TetherMode::Monitor => {
                if verdict.verdict == "halt" {
                    warn!(
                        drift_score = ?verdict.drift_score,
                        feedback = ?verdict.feedback,
                        "TETHER_HALT (monitor mode — not enforcing)"
                    );
                } else if verdict.verdict == "caution" {
                    info!(
                        drift_score = ?verdict.drift_score,
                        "TETHER_CAUTION (monitor mode — not enforcing)"
                    );
                }
                VerdictAction::Continue
            }
            TetherMode::Enforce => match verdict.verdict.as_str() {
                "halt" => {
                    warn!(
                        drift_score = ?verdict.drift_score,
                        feedback = ?verdict.feedback,
                        "TETHER_HALT — terminating sandbox"
                    );
                    VerdictAction::Terminate
                }
                "caution" => {
                    warn!(
                        drift_score = ?verdict.drift_score,
                        feedback = ?verdict.feedback,
                        "TETHER_CAUTION — tightening sandbox policy"
                    );
                    VerdictAction::TightenPolicy {
                        drift_score: verdict.drift_score.unwrap_or(0.0),
                    }
                }
                _ => VerdictAction::Continue,
            },
        }
    }

    /// Convenience: report activity, then execute the verdict.
    pub async fn report_and_enforce(
        &self,
        summaries: &[FlushableActivitySummary],
    ) -> VerdictAction {
        let verdict = self.report_activity(summaries).await;
        self.execute_verdict(&verdict).await
    }
}

/// Return the env var value if it is set and non-empty, otherwise `None`.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Create a [`TetherBridge`] from policy config or environment variables.
///
/// Priority: policy config (from YAML `tether:` section) > env vars.
/// Returns `None` if Tether integration is not enabled.
///
/// Policy YAML example:
/// ```yaml
/// tether:
///   enabled: true
///   endpoint: "http://tether:3000"
///   task_id: "task-abc"
///   mode: enforce
///   report_interval: 30
/// ```
///
/// Environment variable fallback:
/// - `TETHER_ENDPOINT`: Tether server URL (required to enable)
/// - `TETHER_TASK_ID`: Task ID to report against (required)
/// - `TETHER_MODE`: "enforce" or "monitor" (default: "monitor")
/// - `TETHER_TIMEOUT_SECS`: HTTP timeout in seconds (default: 10)
pub fn make_tether_bridge() -> Option<Arc<TetherBridge>> {
    // Try policy-based config first (loaded by caller), then fall back to env vars.
    make_tether_bridge_from_policy(None)
}

/// Create a [`TetherBridge`] from an explicit policy config, with env var fallback.
///
/// When policy config is present, env vars override individual fields so the
/// orchestrator can inject dynamic values (e.g. `TETHER_TASK_ID`) at sandbox
/// creation time without rebuilding the policy YAML.
pub fn make_tether_bridge_from_policy(
    policy_config: Option<&openshell_policy::TetherDef>,
) -> Option<Arc<TetherBridge>> {
    let (endpoint, task_id, mode, timeout_secs) = if let Some(cfg) = policy_config {
        if !cfg.enabled {
            return None;
        }
        // Env vars override policy fields — the orchestrator sets TETHER_TASK_ID
        // dynamically per sandbox run while the policy YAML ships static defaults.
        let endpoint = non_empty_env("TETHER_ENDPOINT")
            .unwrap_or_else(|| cfg.endpoint.clone());
        let task_id = non_empty_env("TETHER_TASK_ID")
            .unwrap_or_else(|| cfg.task_id.clone());
        let mode = match std::env::var("TETHER_MODE")
            .ok()
            .as_deref()
            .or(Some(cfg.mode.as_str()))
        {
            Some("enforce") => TetherMode::Enforce,
            _ => TetherMode::Monitor,
        };
        let timeout_secs: u64 = std::env::var("TETHER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        (endpoint, task_id, mode, timeout_secs)
    } else {
        // Pure env var mode — no policy YAML available
        let endpoint = non_empty_env("TETHER_ENDPOINT")?;
        let task_id = non_empty_env("TETHER_TASK_ID")?;
        let mode = match std::env::var("TETHER_MODE").as_deref() {
            Ok("enforce") => TetherMode::Enforce,
            _ => TetherMode::Monitor,
        };
        let timeout_secs: u64 = std::env::var("TETHER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);
        (endpoint, task_id, mode, timeout_secs)
    };

    if endpoint.is_empty() || task_id.is_empty() {
        return None;
    }

    let config = TetherConfig {
        endpoint,
        task_id,
        mode,
        timeout: Duration::from_secs(timeout_secs),
    };

    info!(
        endpoint = %config.endpoint,
        task_id = %config.task_id,
        mode = ?config.mode,
        "Tether bridge enabled"
    );

    Some(Arc::new(TetherBridge::new(config)))
}
