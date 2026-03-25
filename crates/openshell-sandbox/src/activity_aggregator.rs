// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Activity aggregator — collects and deduplicates proxy allow events.
//!
//! Mirrors the [`DenialAggregator`](crate::denial_aggregator) pattern but
//! tracks *allowed* connections and L7 requests. The Tether bridge consumes
//! the flushed summaries to report ground-truth agent activity for drift
//! detection.

use std::collections::HashMap;
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::debug;

/// A single activity event emitted by the proxy on an allowed connection or
/// L7 request.
#[derive(Debug, Clone)]
pub struct ActivityEvent {
    /// Destination host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Binary path that initiated the connection (if resolved).
    pub binary: String,
    /// Ancestor binary paths from process tree walk.
    pub ancestors: Vec<String>,
    /// Name of the matched network policy rule.
    pub matched_policy: String,
    /// L7 request method (e.g. "GET", "POST") if this is an L7 event.
    pub l7_method: Option<String>,
    /// L7 request path (e.g. "/v1/repos/org/issues") if this is an L7 event.
    pub l7_path: Option<String>,
}

/// Aggregated activity summary keyed by `(host, port, binary)`.
#[derive(Debug, Clone)]
struct AggregatedActivity {
    host: String,
    port: u16,
    binary: String,
    ancestors: Vec<String>,
    matched_policy: String,
    first_seen_ms: i64,
    last_seen_ms: i64,
    count: u32,
    l7_samples: Vec<L7Sample>,
}

/// A single L7 request sample for aggregation.
#[derive(Debug, Clone)]
struct L7Sample {
    method: String,
    path: String,
    count: u32,
}

/// The activity aggregator collects proxy allow events and periodically
/// flushes summaries. Designed to be spawned as a background tokio task.
pub struct ActivityAggregator {
    rx: mpsc::UnboundedReceiver<ActivityEvent>,
    /// Accumulated activities keyed by `(host, port, binary)`.
    summaries: HashMap<(String, u16, String), AggregatedActivity>,
    /// Flush interval in seconds.
    flush_interval_secs: u64,
}

impl ActivityAggregator {
    /// Create a new aggregator that reads from the given channel.
    pub fn new(rx: mpsc::UnboundedReceiver<ActivityEvent>, flush_interval_secs: u64) -> Self {
        Self {
            rx,
            summaries: HashMap::new(),
            flush_interval_secs,
        }
    }

    /// Run the aggregator loop. This consumes `self` and runs until the
    /// channel is closed (all senders are dropped).
    ///
    /// `flush_callback` is called periodically with the accumulated summaries.
    pub async fn run<F, Fut>(mut self, flush_callback: F)
    where
        F: Fn(Vec<FlushableActivitySummary>) -> Fut,
        Fut: Future<Output = ()>,
    {
        let mut flush_interval =
            tokio::time::interval(std::time::Duration::from_secs(self.flush_interval_secs));
        // Don't fire immediately on first tick.
        flush_interval.tick().await;

        loop {
            tokio::select! {
                event = self.rx.recv() => {
                    if let Some(evt) = event {
                        self.ingest(evt);
                    } else {
                        // Channel closed; do a final flush and exit.
                        if !self.summaries.is_empty() {
                            let batch = self.drain();
                            flush_callback(batch).await;
                        }
                        debug!("ActivityAggregator: channel closed, exiting");
                        return;
                    }
                }
                _ = flush_interval.tick() => {
                    if !self.summaries.is_empty() {
                        let batch = self.drain();
                        debug!(count = batch.len(), "ActivityAggregator: flushing summaries");
                        flush_callback(batch).await;
                    }
                }
            }
        }
    }

    /// Ingest a single activity event, merging into existing summary or
    /// creating a new one.
    fn ingest(&mut self, event: ActivityEvent) {
        let now_ms = current_time_ms();
        let key = (event.host.clone(), event.port, event.binary.clone());

        let entry = self
            .summaries
            .entry(key)
            .or_insert_with(|| AggregatedActivity {
                host: event.host.clone(),
                port: event.port,
                binary: event.binary.clone(),
                ancestors: event.ancestors.clone(),
                matched_policy: event.matched_policy.clone(),
                first_seen_ms: now_ms,
                last_seen_ms: now_ms,
                count: 0,
                l7_samples: Vec::new(),
            });

        entry.count += 1;
        entry.last_seen_ms = now_ms;

        // Merge L7 samples (cap at 50 distinct method+path pairs).
        if let (Some(method), Some(path)) = (&event.l7_method, &event.l7_path) {
            if let Some(sample) = entry
                .l7_samples
                .iter_mut()
                .find(|s| s.method == *method && s.path == *path)
            {
                sample.count += 1;
            } else if entry.l7_samples.len() < 50 {
                entry.l7_samples.push(L7Sample {
                    method: method.clone(),
                    path: path.clone(),
                    count: 1,
                });
            }
        }
    }

    /// Drain all accumulated summaries into a flushable batch.
    fn drain(&mut self) -> Vec<FlushableActivitySummary> {
        self.summaries
            .drain()
            .map(|(_, v)| FlushableActivitySummary {
                host: v.host,
                port: v.port,
                binary: v.binary,
                ancestors: v.ancestors,
                matched_policy: v.matched_policy,
                first_seen_ms: v.first_seen_ms,
                last_seen_ms: v.last_seen_ms,
                count: v.count,
                l7_samples: v
                    .l7_samples
                    .into_iter()
                    .map(|s| FlushableL7Sample {
                        method: s.method,
                        path: s.path,
                        count: s.count,
                    })
                    .collect(),
            })
            .collect()
    }
}

/// An activity summary ready to be sent to the Tether bridge.
#[derive(Debug, Clone)]
pub struct FlushableActivitySummary {
    /// Destination host.
    pub host: String,
    /// Destination port.
    pub port: u16,
    /// Binary path that initiated the connection.
    pub binary: String,
    /// Ancestor binary paths.
    pub ancestors: Vec<String>,
    /// Name of the matched network policy rule.
    pub matched_policy: String,
    /// First event timestamp (ms since epoch).
    pub first_seen_ms: i64,
    /// Most recent event timestamp (ms since epoch).
    pub last_seen_ms: i64,
    /// Number of events in this aggregation window.
    pub count: u32,
    /// Observed L7 request patterns.
    pub l7_samples: Vec<FlushableL7Sample>,
}

/// L7 request sample in flushable form.
#[derive(Debug, Clone)]
pub struct FlushableL7Sample {
    pub method: String,
    pub path: String,
    pub count: u32,
}

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_aggregates_and_flushes_on_channel_close() {
        let (tx, rx) = mpsc::unbounded_channel();
        let aggregator = ActivityAggregator::new(rx, 3600); // large interval — won't tick

        let flushed: Arc<Mutex<Vec<FlushableActivitySummary>>> =
            Arc::new(Mutex::new(Vec::new()));
        let flushed_clone = flushed.clone();

        // Send events then drop sender
        tx.send(ActivityEvent {
            host: "api.github.com".into(),
            port: 443,
            binary: "/usr/bin/node".into(),
            ancestors: vec!["/usr/bin/bash".into()],
            matched_policy: "github".into(),
            l7_method: Some("GET".into()),
            l7_path: Some("/repos/org/repo".into()),
        })
        .unwrap();
        tx.send(ActivityEvent {
            host: "api.github.com".into(),
            port: 443,
            binary: "/usr/bin/node".into(),
            ancestors: vec!["/usr/bin/bash".into()],
            matched_policy: "github".into(),
            l7_method: Some("POST".into()),
            l7_path: Some("/repos/org/repo/issues".into()),
        })
        .unwrap();
        // Same method+path as first — should merge
        tx.send(ActivityEvent {
            host: "api.github.com".into(),
            port: 443,
            binary: "/usr/bin/node".into(),
            ancestors: vec!["/usr/bin/bash".into()],
            matched_policy: "github".into(),
            l7_method: Some("GET".into()),
            l7_path: Some("/repos/org/repo".into()),
        })
        .unwrap();
        drop(tx);

        aggregator
            .run(|batch| {
                let f = flushed_clone.clone();
                async move {
                    f.lock().unwrap().extend(batch);
                }
            })
            .await;

        let result = flushed.lock().unwrap();
        assert_eq!(result.len(), 1, "should aggregate into one summary by (host, port, binary)");

        let summary = &result[0];
        assert_eq!(summary.host, "api.github.com");
        assert_eq!(summary.port, 443);
        assert_eq!(summary.binary, "/usr/bin/node");
        assert_eq!(summary.matched_policy, "github");
        assert_eq!(summary.count, 3);
        assert_eq!(summary.l7_samples.len(), 2, "should have 2 distinct method+path pairs");

        // Check GET /repos/org/repo was merged (count=2)
        let get_sample = summary
            .l7_samples
            .iter()
            .find(|s| s.method == "GET")
            .expect("should have GET sample");
        assert_eq!(get_sample.count, 2);

        let post_sample = summary
            .l7_samples
            .iter()
            .find(|s| s.method == "POST")
            .expect("should have POST sample");
        assert_eq!(post_sample.count, 1);
    }

    #[tokio::test]
    async fn test_different_hosts_produce_separate_summaries() {
        let (tx, rx) = mpsc::unbounded_channel();
        let aggregator = ActivityAggregator::new(rx, 3600);

        let flushed: Arc<Mutex<Vec<FlushableActivitySummary>>> =
            Arc::new(Mutex::new(Vec::new()));
        let flushed_clone = flushed.clone();

        tx.send(ActivityEvent {
            host: "api.github.com".into(),
            port: 443,
            binary: "/usr/bin/node".into(),
            ancestors: vec![],
            matched_policy: "github".into(),
            l7_method: None,
            l7_path: None,
        })
        .unwrap();
        tx.send(ActivityEvent {
            host: "api.openai.com".into(),
            port: 443,
            binary: "/usr/bin/node".into(),
            ancestors: vec![],
            matched_policy: "openai".into(),
            l7_method: None,
            l7_path: None,
        })
        .unwrap();
        drop(tx);

        aggregator
            .run(|batch| {
                let f = flushed_clone.clone();
                async move {
                    f.lock().unwrap().extend(batch);
                }
            })
            .await;

        let result = flushed.lock().unwrap();
        assert_eq!(result.len(), 2, "different hosts should produce separate summaries");
    }

    #[tokio::test]
    async fn test_no_events_no_flush() {
        let (tx, rx) = mpsc::unbounded_channel();
        let aggregator = ActivityAggregator::new(rx, 3600);

        let flush_count = Arc::new(Mutex::new(0u32));
        let flush_count_clone = flush_count.clone();

        drop(tx); // close immediately

        aggregator
            .run(|_batch| {
                let c = flush_count_clone.clone();
                async move {
                    *c.lock().unwrap() += 1;
                }
            })
            .await;

        assert_eq!(*flush_count.lock().unwrap(), 0, "no events should mean no flush");
    }
}
