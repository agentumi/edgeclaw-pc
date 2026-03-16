//! Business domain workflows.
//!
//! Provides specialized workflow modules for business operations including:
//! - Report automation
//! - Data analysis and insights
//! - Approval workflows
//! - Business intelligence

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::task_templates::{
    RequiredRole, TaskTemplate, TemplateCategory, TemplateParam, TemplateStep,
};

// --- Data Types ---

/// Report configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Report name
    pub name: String,
    /// Report period
    pub period: String,
    /// Department
    pub department: Option<String>,
    /// Recipients
    pub recipients: Vec<String>,
}

/// Analysis request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    /// Analysis type
    pub analysis_type: String,
    /// Data source
    pub data_source: String,
    /// Parameters
    pub params: HashMap<String, String>,
}

/// Approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Request type (expense, vacation, purchase, contract)
    pub request_type: String,
    /// Requester ID
    pub requester_id: String,
    /// Amount (if applicable)
    pub amount: Option<f64>,
    /// Description
    pub description: String,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Approval result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResult {
    /// Request ID
    pub request_id: String,
    /// Status
    pub status: ApprovalStatus,
    /// Approved by
    pub approved_by: Option<String>,
    /// Approved at
    pub approved_at: Option<String>,
    /// Notes
    pub notes: Option<String>,
}

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

// --- Workflow Functions ---

/// Run weekly sales report workflow
pub fn run_weekly_sales_report(config: &ReportConfig) -> Result<String, String> {
    Ok(format!(
        "Weekly sales report generated for {} - sent to {:?}",
        config.period, config.recipients
    ))
}

/// Run monthly finance report workflow
pub fn run_monthly_finance_report(config: &ReportConfig) -> Result<String, String> {
    Ok(format!(
        "Monthly finance report generated for {} - sent to {:?}",
        config.period, config.recipients
    ))
}

/// Run expense approval workflow
pub fn run_expense_approval(_request: &ApprovalRequest) -> Result<ApprovalResult, String> {
    Ok(ApprovalResult {
        request_id: format!("EXP-{}", uuid::Uuid::new_v4()),
        status: ApprovalStatus::Pending,
        approved_by: None,
        approved_at: None,
        notes: None,
    })
}

/// Run vacation approval workflow
pub fn run_vacation_approval(_request: &ApprovalRequest) -> Result<ApprovalResult, String> {
    Ok(ApprovalResult {
        request_id: format!("VAC-{}", uuid::Uuid::new_v4()),
        status: ApprovalStatus::Pending,
        approved_by: None,
        approved_at: None,
        notes: None,
    })
}

/// Run purchase approval workflow
pub fn run_purchase_approval(_request: &ApprovalRequest) -> Result<ApprovalResult, String> {
    Ok(ApprovalResult {
        request_id: format!("PUR-{}", uuid::Uuid::new_v4()),
        status: ApprovalStatus::Pending,
        approved_by: None,
        approved_at: None,
        notes: None,
    })
}

/// Run KPI alert workflow
pub fn run_kpi_alert(metric_name: &str, value: f64, threshold: f64) -> Result<String, String> {
    let status = if value > threshold { "WARNING" } else { "OK" };
    Ok(format!(
        "KPI Alert: {} = {} (threshold: {}) - {}",
        metric_name, value, threshold, status
    ))
}

// --- Template Registration ---

/// Get all business workflow templates
pub fn get_templates() -> Vec<TaskTemplate> {
    vec![
        // Report Automation
        TaskTemplate {
            id: "biz_weekly_sales".to_string(),
            name: "Weekly Sales Report".to_string(),
            description: "Generate weekly sales report with data collection, analysis, and email delivery".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "report:write".to_string(),
            tags: vec!["business".to_string(), "sales".to_string(), "report".to_string(), "weekly".to_string()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Fetch sales data".to_string(),
                    command: "python".to_string(),
                    args: vec!["scripts/fetch_sales.py".to_string(), "--period".to_string(), "{{period}}".to_string()],
                    working_dir: None,
                    timeout_secs: 60,
                    abort_on_failure: true,
                    optional: false,
                },
                TemplateStep {
                    order: 2,
                    description: "Generate report".to_string(),
                    command: "python".to_string(),
                    args: vec!["scripts/generate_report.py".to_string(), "--type".to_string(), "sales_weekly".to_string()],
                    working_dir: None,
                    timeout_secs: 120,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "period".to_string(),
                    description: "Report period".to_string(),
                    default: Some("last_week".to_string()),
                    required: false,
                    examples: vec!["last_week".to_string(), "this_month".to_string()],
                },
                TemplateParam {
                    name: "recipients".to_string(),
                    description: "Email recipients (comma-separated)".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["team@company.com".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 180,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_monthly_finance".to_string(),
            name: "Monthly Finance Report".to_string(),
            description: "Extract ERP data, generate financial statements, convert to PDF and notify".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "report:write".to_string(),
            tags: vec!["business".to_string(), "finance".to_string(), "report".to_string(), "monthly".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 300,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_quarterly_review".to_string(),
            name: "Quarterly Business Review".to_string(),
            description: "Collect KPIs from all departments, perform comparative analysis, generate review report".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "report:write".to_string(),
            tags: vec!["business".to_string(), "review".to_string(), "quarterly".to_string(), "kpi".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 480,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_client_report".to_string(),
            name: "Client Status Report".to_string(),
            description: "Generate customized report based on client transaction data and growth analysis".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "report:write".to_string(),
            tags: vec!["business".to_string(), "client".to_string(), "report".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "client_id".to_string(),
                    description: "Client ID or name".to_string(),
                    default: None,
                    required: true,
                    examples: vec![],
                },
            ],
            platforms: vec![],
            estimated_secs: 240,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_expense_summary".to_string(),
            name: "Expense Summary".to_string(),
            description: "Collect expense data, categorize by type, and generate visualization".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "report:read".to_string(),
            tags: vec!["business".to_string(), "expense".to_string(), "summary".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        // Data Analysis
        TaskTemplate {
            id: "biz_market_analysis".to_string(),
            name: "Market Competition Analysis".to_string(),
            description: "Collect competitor data, perform SWOT analysis, and generate insights".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "market".to_string(), "analysis".to_string(), "swot".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_customer_segment".to_string(),
            name: "Customer Segmentation".to_string(),
            description: "Analyze transaction data, perform cluster analysis, and propose segment strategies".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "customer".to_string(), "segmentation".to_string(), "ml".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 900,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_trend_forecast".to_string(),
            name: "Trend Forecasting".to_string(),
            description: "Analyze historical data, perform time series analysis, generate forecast report".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "trend".to_string(), "forecast".to_string(), "time_series".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 720,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_churn_prediction".to_string(),
            name: "Churn Prediction".to_string(),
            description: "Analyze customer behavior patterns, run ML inference, generate at-risk customer list".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "churn".to_string(), "prediction".to_string(), "ml".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 480,
            builtin: true,
        },
        // Approval Workflows
        TaskTemplate {
            id: "biz_expense_approval".to_string(),
            name: "Expense Approval".to_string(),
            description: "Process expense claim through department head approval, accounting, and notification".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "approval:write".to_string(),
            tags: vec!["business".to_string(), "expense".to_string(), "approval".to_string(), "workflow".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "amount".to_string(),
                    description: "Expense amount (USD)".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["500".to_string()],
                },
                TemplateParam {
                    name: "description".to_string(),
                    description: "Expense description".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["Business lunch".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_vacation_request".to_string(),
            name: "Vacation Request".to_string(),
            description: "Process vacation request through manager approval, calendar integration, and confirmation".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "approval:write".to_string(),
            tags: vec!["business".to_string(), "vacation".to_string(), "approval".to_string(), "hr".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_purchase_approval".to_string(),
            name: "Purchase Approval".to_string(),
            description: "Validate purchase request against budget, route for approval, process PO".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "approval:write".to_string(),
            tags: vec!["business".to_string(), "purchase".to_string(), "approval".to_string(), "procurement".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_contract_review".to_string(),
            name: "Contract Review".to_string(),
            description: "Upload contract, analyze terms, assess risks, and route for approval".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "legal:write".to_string(),
            tags: vec!["business".to_string(), "contract".to_string(), "review".to_string(), "legal".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 300,
            builtin: true,
        },
        // Business Intelligence
        TaskTemplate {
            id: "biz_dashboard_sync".to_string(),
            name: "Dashboard Data Sync".to_string(),
            description: "Sync data from multiple sources, aggregate, and update dashboard".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "dashboard".to_string(), "sync".to_string(), "data".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_kpi_alert".to_string(),
            name: "KPI Alert".to_string(),
            description: "Monitor real-time KPIs, detect threshold breaches, send alerts with recommendations".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "kpi".to_string(), "alert".to_string(), "monitoring".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_benchmark_report".to_string(),
            name: "Benchmark Report".to_string(),
            description: "Collect industry data, compare with company metrics, generate strategic recommendations".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "benchmark".to_string(), "report".to_string(), "strategy".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 1200,
            builtin: true,
        },
        TaskTemplate {
            id: "biz_competitor_watch".to_string(),
            name: "Competitor Monitoring".to_string(),
            description: "Monitor competitor news and products, summarize, generate periodic reports".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "analytics:read".to_string(),
            tags: vec!["business".to_string(), "competitor".to_string(), "monitoring".to_string(), "research".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 900,
            builtin: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expense_approval() {
        let request = ApprovalRequest {
            request_type: "expense".to_string(),
            requester_id: "user123".to_string(),
            amount: Some(500.0),
            description: "Business lunch".to_string(),
            metadata: HashMap::new(),
        };

        let result = run_expense_approval(&request);
        assert!(result.is_ok());
        let approval = result.unwrap();
        assert_eq!(approval.status, ApprovalStatus::Pending);
    }

    #[test]
    fn test_kpi_alert() {
        let result = run_kpi_alert("revenue", 150000.0, 100000.0);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("WARNING"));
    }
}
