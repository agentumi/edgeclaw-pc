//! Kubernetes CRD and operator types for EdgeClaw.
//!
//! Defines [`EdgeClawAgentSpec`] custom resource, [`Reconciler`] logic,
//! and Helm chart value types for Kubernetes-native deployment.

use serde::{Deserialize, Serialize};

use crate::error::AgentError;

/// Kubernetes API version for EdgeClaw CRD.
pub const CRD_API_VERSION: &str = "edgeclaw.io/v1alpha1";
/// CRD kind.
pub const CRD_KIND: &str = "EdgeClawAgent";

/// EdgeClawAgent custom resource spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeClawAgentSpec {
    /// Agent name.
    pub name: String,
    /// Number of replicas.
    pub replicas: u32,
    /// Container image.
    pub image: String,
    /// Listen port.
    pub listen_port: u16,
    /// Web UI port.
    pub web_ui_port: u16,
    /// Resource requests.
    pub resources: ResourceRequirements,
    /// Federation enabled.
    pub federation_enabled: bool,
    /// TEE enabled.
    pub tee_enabled: bool,
    /// Auto-scaling config.
    pub autoscaling: Option<AutoscalingSpec>,
}

impl Default for EdgeClawAgentSpec {
    fn default() -> Self {
        Self {
            name: "edgeclaw-agent".into(),
            replicas: 1,
            image: "ghcr.io/agentumi/edgeclaw-agent:latest".into(),
            listen_port: 8443,
            web_ui_port: 9444,
            resources: ResourceRequirements::default(),
            federation_enabled: false,
            tee_enabled: false,
            autoscaling: None,
        }
    }
}

/// Kubernetes resource requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    /// CPU request (millicores).
    pub cpu_request: String,
    /// Memory request.
    pub memory_request: String,
    /// CPU limit.
    pub cpu_limit: String,
    /// Memory limit.
    pub memory_limit: String,
}

impl Default for ResourceRequirements {
    fn default() -> Self {
        Self {
            cpu_request: "100m".into(),
            memory_request: "64Mi".into(),
            cpu_limit: "500m".into(),
            memory_limit: "256Mi".into(),
        }
    }
}

/// Autoscaling specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoscalingSpec {
    /// Minimum replicas.
    pub min_replicas: u32,
    /// Maximum replicas.
    pub max_replicas: u32,
    /// Target CPU utilization (%).
    pub target_cpu_utilization: u32,
    /// Target memory utilization (%).
    pub target_memory_utilization: Option<u32>,
    /// Scale-down stabilization window (seconds).
    pub scale_down_stabilization_secs: u32,
}

impl Default for AutoscalingSpec {
    fn default() -> Self {
        Self {
            min_replicas: 1,
            max_replicas: 10,
            target_cpu_utilization: 70,
            target_memory_utilization: None,
            scale_down_stabilization_secs: 300,
        }
    }
}

/// CRD status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeClawAgentStatus {
    /// Current replicas.
    pub ready_replicas: u32,
    /// Available replicas.
    pub available_replicas: u32,
    /// Conditions.
    pub conditions: Vec<StatusCondition>,
    /// Last observed generation.
    pub observed_generation: u64,
}

/// Status condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusCondition {
    /// Condition type.
    pub condition_type: String,
    /// Status (True/False/Unknown).
    pub status: String,
    /// Reason.
    pub reason: String,
    /// Message.
    pub message: String,
    /// Last transition time.
    pub last_transition: chrono::DateTime<chrono::Utc>,
}

/// Reconcile action to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Create the deployment.
    Create,
    /// Update existing deployment.
    Update,
    /// Scale replicas.
    Scale(u32),
    /// Delete the deployment.
    Delete,
    /// No action needed.
    NoOp,
}

/// Reconciler for EdgeClawAgent CRD.
pub struct Reconciler {
    namespace: String,
}

impl Reconciler {
    /// Create a new reconciler.
    pub fn new(namespace: &str) -> Self {
        Self {
            namespace: namespace.to_string(),
        }
    }

    /// Determine reconcile action based on desired vs actual state.
    pub fn reconcile(
        &self,
        spec: &EdgeClawAgentSpec,
        current_replicas: Option<u32>,
    ) -> ReconcileAction {
        match current_replicas {
            None => ReconcileAction::Create,
            Some(current) if current != spec.replicas => ReconcileAction::Scale(spec.replicas),
            Some(_) => ReconcileAction::NoOp,
        }
    }

    /// Generate Kubernetes Deployment manifest (YAML string).
    pub fn generate_deployment_yaml(&self, spec: &EdgeClawAgentSpec) -> String {
        format!(
            r#"apiVersion: apps/v1
kind: Deployment
metadata:
  name: {}
  namespace: {}
  labels:
    app: edgeclaw-agent
spec:
  replicas: {}
  selector:
    matchLabels:
      app: edgeclaw-agent
  template:
    metadata:
      labels:
        app: edgeclaw-agent
    spec:
      containers:
      - name: edgeclaw-agent
        image: {}
        ports:
        - containerPort: {}
          name: ecnp
        - containerPort: {}
          name: webui
        resources:
          requests:
            cpu: "{}"
            memory: "{}"
          limits:
            cpu: "{}"
            memory: "{}"
"#,
            spec.name,
            self.namespace,
            spec.replicas,
            spec.image,
            spec.listen_port,
            spec.web_ui_port,
            spec.resources.cpu_request,
            spec.resources.memory_request,
            spec.resources.cpu_limit,
            spec.resources.memory_limit,
        )
    }

    /// Generate Service manifest.
    pub fn generate_service_yaml(&self, spec: &EdgeClawAgentSpec) -> String {
        format!(
            r#"apiVersion: v1
kind: Service
metadata:
  name: {}-svc
  namespace: {}
spec:
  selector:
    app: edgeclaw-agent
  ports:
  - name: ecnp
    port: {}
    targetPort: {}
  - name: webui
    port: {}
    targetPort: {}
  type: ClusterIP
"#,
            spec.name,
            self.namespace,
            spec.listen_port,
            spec.listen_port,
            spec.web_ui_port,
            spec.web_ui_port,
        )
    }

    /// Generate HPA manifest.
    pub fn generate_hpa_yaml(&self, spec: &EdgeClawAgentSpec) -> Result<String, AgentError> {
        let hpa = spec
            .autoscaling
            .as_ref()
            .ok_or_else(|| AgentError::InvalidParameter("No autoscaling config".into()))?;

        Ok(format!(
            r#"apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {}-hpa
  namespace: {}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {}
  minReplicas: {}
  maxReplicas: {}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {}
  behavior:
    scaleDown:
      stabilizationWindowSeconds: {}
"#,
            spec.name,
            self.namespace,
            spec.name,
            hpa.min_replicas,
            hpa.max_replicas,
            hpa.target_cpu_utilization,
            hpa.scale_down_stabilization_secs,
        ))
    }

    /// Get namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

/// Helm chart values structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelmValues {
    /// Agent spec.
    pub agent: EdgeClawAgentSpec,
    /// Ingress enabled.
    pub ingress_enabled: bool,
    /// TLS enabled.
    pub tls_enabled: bool,
    /// Node selector.
    pub node_selector: std::collections::HashMap<String, String>,
    /// Tolerations.
    pub tolerations: Vec<String>,
}

impl Default for HelmValues {
    fn default() -> Self {
        Self {
            agent: EdgeClawAgentSpec::default(),
            ingress_enabled: false,
            tls_enabled: true,
            node_selector: std::collections::HashMap::new(),
            tolerations: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_default() {
        let spec = EdgeClawAgentSpec::default();
        assert_eq!(spec.replicas, 1);
        assert_eq!(spec.listen_port, 8443);
        assert!(!spec.federation_enabled);
    }

    #[test]
    fn test_resource_requirements_default() {
        let res = ResourceRequirements::default();
        assert_eq!(res.cpu_request, "100m");
        assert_eq!(res.memory_limit, "256Mi");
    }

    #[test]
    fn test_autoscaling_default() {
        let auto = AutoscalingSpec::default();
        assert_eq!(auto.min_replicas, 1);
        assert_eq!(auto.max_replicas, 10);
        assert_eq!(auto.target_cpu_utilization, 70);
    }

    #[test]
    fn test_reconcile_create() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec::default();
        assert_eq!(r.reconcile(&spec, None), ReconcileAction::Create);
    }

    #[test]
    fn test_reconcile_scale() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec {
            replicas: 3,
            ..Default::default()
        };
        assert_eq!(r.reconcile(&spec, Some(1)), ReconcileAction::Scale(3));
    }

    #[test]
    fn test_reconcile_noop() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec::default();
        assert_eq!(r.reconcile(&spec, Some(1)), ReconcileAction::NoOp);
    }

    #[test]
    fn test_generate_deployment_yaml() {
        let r = Reconciler::new("edgeclaw");
        let spec = EdgeClawAgentSpec::default();
        let yaml = r.generate_deployment_yaml(&spec);
        assert!(yaml.contains("kind: Deployment"));
        assert!(yaml.contains("namespace: edgeclaw"));
        assert!(yaml.contains("replicas: 1"));
    }

    #[test]
    fn test_generate_service_yaml() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec::default();
        let yaml = r.generate_service_yaml(&spec);
        assert!(yaml.contains("kind: Service"));
        assert!(yaml.contains("port: 8443"));
    }

    #[test]
    fn test_generate_hpa_yaml() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec {
            autoscaling: Some(AutoscalingSpec::default()),
            ..Default::default()
        };
        let yaml = r.generate_hpa_yaml(&spec).unwrap();
        assert!(yaml.contains("HorizontalPodAutoscaler"));
        assert!(yaml.contains("maxReplicas: 10"));
    }

    #[test]
    fn test_generate_hpa_no_config() {
        let r = Reconciler::new("default");
        let spec = EdgeClawAgentSpec::default();
        assert!(r.generate_hpa_yaml(&spec).is_err());
    }

    #[test]
    fn test_helm_values_default() {
        let values = HelmValues::default();
        assert!(!values.ingress_enabled);
        assert!(values.tls_enabled);
    }

    #[test]
    fn test_spec_serialize() {
        let spec = EdgeClawAgentSpec::default();
        let json = serde_json::to_string(&spec).unwrap();
        let parsed: EdgeClawAgentSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "edgeclaw-agent");
    }

    #[test]
    fn test_status_condition_serialize() {
        let cond = StatusCondition {
            condition_type: "Available".into(),
            status: "True".into(),
            reason: "MinimumReplicasAvailable".into(),
            message: "Deployment has minimum availability".into(),
            last_transition: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&cond).unwrap();
        let parsed: StatusCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.condition_type, "Available");
    }
}
