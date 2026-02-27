//! Prometheus-compatible metrics collection and exposition.
//!
//! Provides [`MetricsRegistry`] for tracking counters, gauges, and histograms,
//! plus a `GET /metrics` text-format endpoint renderer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A single metric value.
#[derive(Debug, Clone, serde::Serialize)]
pub enum MetricValue {
    /// Monotonically increasing counter.
    Counter(f64),
    /// Value that can go up and down.
    Gauge(f64),
    /// Distribution of values with pre-defined buckets.
    Histogram {
        count: u64,
        sum: f64,
        buckets: Vec<(f64, u64)>,
    },
}

/// Metadata for a metric.
#[derive(Debug, Clone)]
struct MetricMeta {
    help: String,
    mtype: &'static str,
    value: MetricValue,
}

/// Thread-safe metrics registry.
#[derive(Debug, Clone)]
pub struct MetricsRegistry {
    inner: Arc<Mutex<HashMap<String, MetricMeta>>>,
}

/// Default histogram buckets for command duration.
pub const DEFAULT_BUCKETS: &[f64] = &[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0];

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a registry pre-populated with standard EdgeClaw metrics.
    pub fn with_defaults() -> Self {
        let reg = Self::new();
        // Gauges
        reg.register_gauge("edgeclaw_active_peers", "Number of active peer connections");
        reg.register_gauge(
            "edgeclaw_active_sessions",
            "Number of active encrypted sessions",
        );
        reg.register_gauge("edgeclaw_cpu_usage_percent", "Current CPU usage percentage");
        reg.register_gauge(
            "edgeclaw_memory_usage_bytes",
            "Current memory usage in bytes",
        );

        // Counters
        reg.register_counter(
            "edgeclaw_commands_total",
            "Total commands executed since start",
        );
        reg.register_counter(
            "edgeclaw_messages_total",
            "Total ECNP messages processed since start",
        );
        reg.register_counter(
            "edgeclaw_errors_total",
            "Total errors encountered since start",
        );

        // Histogram
        reg.register_histogram(
            "edgeclaw_command_duration_seconds",
            "Command execution duration in seconds",
            DEFAULT_BUCKETS,
        );

        reg
    }

    /// Register a new counter metric.
    pub fn register_counter(&self, name: &str, help: &str) {
        let mut map = self.inner.lock().unwrap();
        map.insert(
            name.to_string(),
            MetricMeta {
                help: help.to_string(),
                mtype: "counter",
                value: MetricValue::Counter(0.0),
            },
        );
    }

    /// Register a new gauge metric.
    pub fn register_gauge(&self, name: &str, help: &str) {
        let mut map = self.inner.lock().unwrap();
        map.insert(
            name.to_string(),
            MetricMeta {
                help: help.to_string(),
                mtype: "gauge",
                value: MetricValue::Gauge(0.0),
            },
        );
    }

    /// Register a new histogram metric.
    pub fn register_histogram(&self, name: &str, help: &str, buckets: &[f64]) {
        let mut map = self.inner.lock().unwrap();
        let bucket_vec: Vec<(f64, u64)> = buckets.iter().map(|&b| (b, 0)).collect();
        map.insert(
            name.to_string(),
            MetricMeta {
                help: help.to_string(),
                mtype: "histogram",
                value: MetricValue::Histogram {
                    count: 0,
                    sum: 0.0,
                    buckets: bucket_vec,
                },
            },
        );
    }

    /// Increment a counter by the given amount.
    pub fn inc_counter(&self, name: &str, amount: f64) {
        let mut map = self.inner.lock().unwrap();
        if let Some(meta) = map.get_mut(name) {
            if let MetricValue::Counter(ref mut v) = meta.value {
                *v += amount;
            }
        }
    }

    /// Set a gauge to an absolute value.
    pub fn set_gauge(&self, name: &str, value: f64) {
        let mut map = self.inner.lock().unwrap();
        if let Some(meta) = map.get_mut(name) {
            if let MetricValue::Gauge(ref mut v) = meta.value {
                *v = value;
            }
        }
    }

    /// Record an observation in a histogram.
    pub fn observe_histogram(&self, name: &str, value: f64) {
        let mut map = self.inner.lock().unwrap();
        if let Some(meta) = map.get_mut(name) {
            if let MetricValue::Histogram {
                ref mut count,
                ref mut sum,
                ref mut buckets,
            } = meta.value
            {
                *count += 1;
                *sum += value;
                for (bound, cnt) in buckets.iter_mut() {
                    if value <= *bound {
                        *cnt += 1;
                    }
                }
            }
        }
    }

    /// Get the current value of a metric.
    pub fn get(&self, name: &str) -> Option<MetricValue> {
        let map = self.inner.lock().unwrap();
        map.get(name).map(|m| m.value.clone())
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let map = self.inner.lock().unwrap();
        let mut output = String::new();

        let mut names: Vec<&String> = map.keys().collect();
        names.sort();

        for name in names {
            let meta = &map[name];
            output.push_str(&format!("# HELP {} {}\n", name, meta.help));
            output.push_str(&format!("# TYPE {} {}\n", name, meta.mtype));

            match &meta.value {
                MetricValue::Counter(v) => {
                    output.push_str(&format!("{name} {v}\n"));
                }
                MetricValue::Gauge(v) => {
                    output.push_str(&format!("{name} {v}\n"));
                }
                MetricValue::Histogram {
                    count,
                    sum,
                    buckets,
                } => {
                    for (bound, cnt) in buckets {
                        output.push_str(&format!("{name}_bucket{{le=\"{bound}\"}} {cnt}\n"));
                    }
                    output.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {count}\n"));
                    output.push_str(&format!("{name}_sum {sum}\n"));
                    output.push_str(&format!("{name}_count {count}\n"));
                }
            }
            output.push('\n');
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_inc_counter() {
        let reg = MetricsRegistry::new();
        reg.register_counter("test_total", "A test counter");
        reg.inc_counter("test_total", 1.0);
        reg.inc_counter("test_total", 2.0);
        match reg.get("test_total") {
            Some(MetricValue::Counter(v)) => assert!((v - 3.0).abs() < f64::EPSILON),
            _ => panic!("Expected counter"),
        }
    }

    #[test]
    fn test_set_gauge() {
        let reg = MetricsRegistry::new();
        reg.register_gauge("test_gauge", "A test gauge");
        reg.set_gauge("test_gauge", 42.0);
        match reg.get("test_gauge") {
            Some(MetricValue::Gauge(v)) => assert!((v - 42.0).abs() < f64::EPSILON),
            _ => panic!("Expected gauge"),
        }
        // Overwrite
        reg.set_gauge("test_gauge", 10.0);
        match reg.get("test_gauge") {
            Some(MetricValue::Gauge(v)) => assert!((v - 10.0).abs() < f64::EPSILON),
            _ => panic!("Expected gauge"),
        }
    }

    #[test]
    fn test_observe_histogram() {
        let reg = MetricsRegistry::new();
        reg.register_histogram("test_duration", "A test histogram", &[0.1, 0.5, 1.0, 5.0]);
        reg.observe_histogram("test_duration", 0.05);
        reg.observe_histogram("test_duration", 0.3);
        reg.observe_histogram("test_duration", 2.0);
        match reg.get("test_duration") {
            Some(MetricValue::Histogram {
                count,
                sum,
                buckets,
            }) => {
                assert_eq!(count, 3);
                assert!((sum - 2.35).abs() < 0.001);
                // 0.1 bucket: 0.05 fits → 1
                assert_eq!(buckets[0].1, 1);
                // 0.5 bucket: 0.05, 0.3 fit → 2
                assert_eq!(buckets[1].1, 2);
                // 1.0 bucket: 0.05, 0.3 fit → 2
                assert_eq!(buckets[2].1, 2);
                // 5.0 bucket: all fit → 3
                assert_eq!(buckets[3].1, 3);
            }
            _ => panic!("Expected histogram"),
        }
    }

    #[test]
    fn test_prometheus_text_format() {
        let reg = MetricsRegistry::new();
        reg.register_counter("http_requests_total", "Total HTTP requests");
        reg.inc_counter("http_requests_total", 5.0);
        let text = reg.render_prometheus();
        assert!(text.contains("# HELP http_requests_total Total HTTP requests"));
        assert!(text.contains("# TYPE http_requests_total counter"));
        assert!(text.contains("http_requests_total 5"));
    }

    #[test]
    fn test_histogram_text_format() {
        let reg = MetricsRegistry::new();
        reg.register_histogram("cmd_duration", "Duration", &[0.1, 1.0]);
        reg.observe_histogram("cmd_duration", 0.5);
        let text = reg.render_prometheus();
        assert!(text.contains("cmd_duration_bucket{le=\"0.1\"} 0"));
        assert!(text.contains("cmd_duration_bucket{le=\"1\"} 1"));
        assert!(text.contains("cmd_duration_bucket{le=\"+Inf\"} 1"));
        assert!(text.contains("cmd_duration_sum 0.5"));
        assert!(text.contains("cmd_duration_count 1"));
    }

    #[test]
    fn test_with_defaults() {
        let reg = MetricsRegistry::with_defaults();
        assert!(reg.get("edgeclaw_active_peers").is_some());
        assert!(reg.get("edgeclaw_active_sessions").is_some());
        assert!(reg.get("edgeclaw_commands_total").is_some());
        assert!(reg.get("edgeclaw_messages_total").is_some());
        assert!(reg.get("edgeclaw_errors_total").is_some());
        assert!(reg.get("edgeclaw_cpu_usage_percent").is_some());
        assert!(reg.get("edgeclaw_memory_usage_bytes").is_some());
        assert!(reg.get("edgeclaw_command_duration_seconds").is_some());
    }

    #[test]
    fn test_nonexistent_metric() {
        let reg = MetricsRegistry::new();
        assert!(reg.get("does_not_exist").is_none());
        // These should silently do nothing
        reg.inc_counter("does_not_exist", 1.0);
        reg.set_gauge("does_not_exist", 1.0);
        reg.observe_histogram("does_not_exist", 1.0);
    }

    #[test]
    fn test_thread_safety() {
        let reg = MetricsRegistry::with_defaults();
        let reg2 = reg.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..100 {
                reg2.inc_counter("edgeclaw_commands_total", 1.0);
            }
        });
        for _ in 0..100 {
            reg.inc_counter("edgeclaw_commands_total", 1.0);
        }
        handle.join().unwrap();
        match reg.get("edgeclaw_commands_total") {
            Some(MetricValue::Counter(v)) => assert!((v - 200.0).abs() < f64::EPSILON),
            _ => panic!("Expected counter"),
        }
    }
}
