//! Investment domain workflows.
//!
//! Provides specialized workflow modules for investment operations including:
//! - Market research and analysis
//! - Due diligence (company, technical, financial, legal)
//! - Portfolio management
//! - Investment analysis
//! - Investment process automation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::task_templates::{
    TemplateCategory, TemplateStep, TemplateParam, RequiredRole, TaskTemplate,
};

/// Investment domain categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestmentCategory {
    /// Market research and analysis
    MarketResearch,
    /// Due diligence operations
    DueDiligence,
    /// Portfolio management
    PortfolioManagement,
    /// Investment analysis
    InvestmentAnalysis,
    /// Investment process
    InvestmentProcess,
}

impl std::fmt::Display for InvestmentCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvestmentCategory::MarketResearch => write!(f, "Market Research"),
            InvestmentCategory::DueDiligence => write!(f, "Due Diligence"),
            InvestmentCategory::PortfolioManagement => write!(f, "Portfolio Management"),
            InvestmentCategory::InvestmentAnalysis => write!(f, "Investment Analysis"),
            InvestmentCategory::InvestmentProcess => write!(f, "Investment Process"),
        }
    }
}

/// Market data source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketDataSource {
    /// Source name (e.g., "Yahoo Finance", "Bloomberg", "FRED")
    pub source: String,
    /// Data type (e.g., "stock", "index", "economic")
    pub data_type: String,
    /// Ticker symbol or indicator code
    pub identifier: String,
}

/// Financial metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinancialMetric {
    /// Metric name
    pub name: String,
    /// Metric value
    pub value: f64,
    /// Unit (percentage, ratio, etc.)
    pub unit: String,
    /// Period (e.g., "Q4 2025", "FY2025")
    pub period: String,
}

/// Company profile for due diligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyProfile {
    /// Company name
    pub name: String,
    /// Stock ticker
    pub ticker: Option<String>,
    /// Industry sector
    pub sector: String,
    /// Market cap in USD
    pub market_cap_usd: Option<f64>,
    /// Key products/services
    pub products: Vec<String>,
    /// Key competitors
    pub competitors: Vec<String>,
}

/// Portfolio position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioPosition {
    /// Asset ticker
    pub ticker: String,
    /// Number of shares
    pub shares: f64,
    /// Average cost basis
    pub avg_cost: f64,
    /// Current price
    pub current_price: f64,
    /// Target allocation percentage
    pub target_allocation: f64,
}

/// Investment pipeline deal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestmentDeal {
    /// Deal ID
    pub deal_id: String,
    /// Company name
    pub company: String,
    /// Deal stage
    pub stage: DealStage,
    /// Investment amount (USD)
    pub amount_usd: Option<f64>,
    /// Deal date
    pub date: String,
    /// Notes
    pub notes: Option<String>,
}

/// Deal stages in investment pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DealStage {
    /// Initial screening
    Screening,
    /// First meeting conducted
    FirstMeeting,
    /// Due diligence in progress
    DueDiligence,
    /// Term sheet offered
    TermSheet,
    /// Final negotiation
    Negotiation,
    /// Deal closed
    Closed,
    /// Deal passed
    Passed,
}

impl std::fmt::Display for DealStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DealStage::Screening => write!(f, "Screening"),
            DealStage::FirstMeeting => write!(f, "First Meeting"),
            DealStage::DueDiligence => write!(f, "Due Diligence"),
            DealStage::TermSheet => write!(f, "Term Sheet"),
            DealStage::Negotiation => write!(f, "Negotiation"),
            DealStage::Closed => write!(f, "Closed"),
            DealStage::Passed => write!(f, "Passed"),
        }
    }
}

/// Workflow result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowResult<T> {
    /// Whether the workflow succeeded
    pub success: bool,
    /// Result data
    pub data: Option<T>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

impl<T> WorkflowResult<T> {
    /// Create a success result
    pub fn success(data: T, exec_time_ms: u64) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            execution_time_ms: exec_time_ms,
        }
    }

    /// Create an error result
    pub fn error(msg: String, exec_time_ms: u64) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg),
            execution_time_ms: exec_time_ms,
        }
    }
}

// --- Portfolio Management Workflows ---

/// Portfolio rebalancing workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioRebalanceWorkflow {
    /// Current positions
    pub positions: Vec<PortfolioPosition>,
    /// Target allocation (ticker -> percentage)
    pub target_allocation: HashMap<String, f64>,
    /// Cash available for investment
    pub cash_available: f64,
    /// Rebalancing threshold (%)
    pub threshold_percent: Option<f64>,
}

impl Default for PortfolioRebalanceWorkflow {
    fn default() -> Self {
        Self {
            positions: Vec::new(),
            target_allocation: HashMap::new(),
            cash_available: 0.0,
            threshold_percent: Some(5.0),
        }
    }
}

/// Rebalancing recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RebalanceRecommendation {
    /// Ticker
    pub ticker: String,
    /// Action (buy/sell/hold)
    pub action: RebalanceAction,
    /// Number of shares
    pub shares: f64,
    /// Estimated value (USD)
    pub value_usd: f64,
    /// Reason
    pub reason: String,
}

/// Rebalance action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RebalanceAction {
    /// Buy more
    Buy,
    /// Sell
    Sell,
    /// Hold current position
    Hold,
}

/// Portfolio rebalance result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortfolioRebalanceResult {
    /// Current total value
    pub current_total_value: f64,
    /// Current allocation
    pub current_allocation: HashMap<String, f64>,
    /// Target allocation
    pub target_allocation: HashMap<String, f64>,
    /// Recommended actions
    pub recommendations: Vec<RebalanceRecommendation>,
    /// Estimated transaction costs
    pub estimated_costs_usd: f64,
    /// Generated at
    pub generated_at: String,
}

/// Run portfolio rebalancing workflow
pub fn run_portfolio_rebalance(input: &PortfolioRebalanceWorkflow) -> WorkflowResult<PortfolioRebalanceResult> {
    let start = std::time::Instant::now();
    
    if input.positions.is_empty() {
        return WorkflowResult::error(
            "Portfolio positions are required".to_string(),
            start.elapsed().as_millis() as u64
        );
    }

    let mut current_total = 0.0;
    let mut current_allocation: HashMap<String, f64> = HashMap::new();
    let mut recommendations: Vec<RebalanceRecommendation> = Vec::new();
    let threshold = input.threshold_percent.unwrap_or(5.0);

    // Calculate current total and allocation
    for pos in &input.positions {
        let value = pos.shares * pos.current_price;
        current_total += value;
    }

    for pos in &input.positions {
        let value = pos.shares * pos.current_price;
        let alloc_pct = (value / current_total) * 100.0;
        current_allocation.insert(pos.ticker.clone(), alloc_pct);

        // Calculate target
        let target = input.target_allocation.get(&pos.ticker).copied().unwrap_or(0.0);
        let diff = alloc_pct - target;

        // Generate recommendation if beyond threshold
        if diff.abs() > threshold {
            let (action, shares, reason) = if diff > 0.0 {
                let excess_value = (diff / 100.0) * current_total;
                let shares_to_sell = (excess_value / pos.current_price).floor();
                (
                    RebalanceAction::Sell,
                    shares_to_sell,
                    format!("Current allocation {}% exceeds target {}% by {}%", 
                        alloc_pct.round(), target.round(), diff.round())
                )
            } else {
                let shortage_value = (-diff / 100.0) * current_total;
                let shares_to_buy = (shortage_value / pos.current_price).floor();
                (
                    RebalanceAction::Buy,
                    shares_to_buy,
                    format!("Current allocation {}% below target {}% by {}%", 
                        alloc_pct.round(), target.round(), (-diff).round())
                )
            };

            if shares > 0.0 {
                recommendations.push(RebalanceRecommendation {
                    ticker: pos.ticker.clone(),
                    action,
                    shares,
                    value_usd: shares * pos.current_price,
                    reason,
                });
            }
        }
    }

    let result = PortfolioRebalanceResult {
        current_total_value: current_total + input.cash_available,
        current_allocation,
        target_allocation: input.target_allocation.clone(),
        recommendations,
        estimated_costs_usd: 0.0,
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    WorkflowResult::success(result, start.elapsed().as_millis() as u64)
}

/// Risk report workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReportWorkflow {
    /// Portfolio positions
    pub positions: Vec<PortfolioPosition>,
    /// Confidence level for VaR (e.g., 0.95, 0.99)
    pub confidence_level: Option<f64>,
    /// Historical period for calculation (days)
    pub history_days: Option<u32>,
}

impl Default for RiskReportWorkflow {
    fn default() -> Self {
        Self {
            positions: Vec::new(),
            confidence_level: Some(0.95),
            history_days: Some(252),
        }
    }
}

/// Risk metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskMetrics {
    /// Value at Risk
    pub var: f64,
    /// Expected Shortfall
    pub expected_shortfall: f64,
    /// Portfolio volatility (annualized)
    pub volatility_annualized: f64,
    /// Beta (if benchmark provided)
    pub beta: Option<f64>,
    /// Sharpe ratio
    pub sharpe_ratio: Option<f64>,
    /// Maximum drawdown
    pub max_drawdown: Option<f64>,
}

/// Risk report result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskReportResult {
    /// Risk metrics
    pub metrics: RiskMetrics,
    /// Risk level assessment
    pub risk_level: String,
    /// Recommendations
    pub recommendations: Vec<String>,
    /// Generated at
    pub generated_at: String,
}

/// Run risk report workflow
pub fn run_risk_report(_input: &RiskReportWorkflow) -> WorkflowResult<RiskReportResult> {
    let start = std::time::Instant::now();
    
    // Calculate simplified risk metrics (placeholder implementation)
    let metrics = RiskMetrics {
        var: 150_000.0,
        expected_shortfall: 200_000.0,
        volatility_annualized: 15.5,
        beta: Some(1.1),
        sharpe_ratio: Some(0.85),
        max_drawdown: Some(-12.5),
    };

    let risk_level = if metrics.volatility_annualized > 20.0 {
        "High"
    } else if metrics.volatility_annualized > 10.0 {
        "Medium"
    } else {
        "Low"
    }.to_string();

    let result = RiskReportResult {
        metrics,
        risk_level,
        recommendations: vec![
            "Consider diversifying across sectors".to_string(),
            "Review exposure to high-volatility assets".to_string(),
            "Consider hedging strategies for downside protection".to_string(),
        ],
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    WorkflowResult::success(result, start.elapsed().as_millis() as u64)
}

// --- Investment Analysis Workflows ---

/// Equity valuation workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquityValuationWorkflow {
    /// Company profile
    pub company: CompanyProfile,
    /// Financial statements
    pub financials: CompanyFinancials,
    /// Valuation method
    pub method: ValuationMethod,
    /// Discount rate (WACC)
    pub discount_rate: Option<f64>,
    /// Terminal growth rate
    pub terminal_growth: Option<f64>,
}

impl Default for EquityValuationWorkflow {
    fn default() -> Self {
        Self {
            company: CompanyProfile {
                name: String::new(),
                ticker: None,
                sector: String::new(),
                market_cap_usd: None,
                products: Vec::new(),
                competitors: Vec::new(),
            },
            financials: CompanyFinancials {
                name: String::new(),
                revenue: None,
                net_income: None,
                ebitda: None,
                pe_ratio: None,
                debt_equity: None,
                roe: None,
            },
            method: ValuationMethod::Dcf,
            discount_rate: Some(0.10),
            terminal_growth: Some(0.03),
        }
    }
}

/// Valuation methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValuationMethod {
    /// Discounted Cash Flow
    Dcf,
    /// Dividend Discount Model
    Ddm,
    /// Relative valuation (P/E)
    Relative,
    /// Asset-based valuation
    AssetBased,
}

impl std::fmt::Display for ValuationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValuationMethod::Dcf => write!(f, "DCF"),
            ValuationMethod::Ddm => write!(f, "DDM"),
            ValuationMethod::Relative => write!(f, "Relative"),
            ValuationMethod::AssetBased => write!(f, "Asset-Based"),
        }
    }
}

/// Company financial data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyFinancials {
    /// Company name
    pub name: String,
    /// Revenue
    pub revenue: Option<f64>,
    /// Net income
    pub net_income: Option<f64>,
    /// EBITDA
    pub ebitda: Option<f64>,
    /// P/E ratio
    pub pe_ratio: Option<f64>,
    /// Debt/Equity ratio
    pub debt_equity: Option<f64>,
    /// ROE
    pub roe: Option<f64>,
}

/// Valuation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValuationResult {
    /// Company name
    pub company: String,
    /// Valuation method used
    pub method: ValuationMethod,
    /// Fair value per share
    pub fair_value_per_share: f64,
    /// Current market price
    pub current_price: Option<f64>,
    /// Upside/downside %
    pub upside_percent: Option<f64>,
    /// Key assumptions
    pub assumptions: HashMap<String, f64>,
    /// Sensitivity analysis
    pub sensitivity: Vec<SensitivityRow>,
    /// Generated at
    pub generated_at: String,
}

/// Sensitivity analysis row
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensitivityRow {
    /// Discount rate
    pub discount_rate: f64,
    /// Terminal growth rate
    pub terminal_growth: f64,
    /// Fair value
    pub fair_value: f64,
}

/// Run equity valuation workflow
pub fn run_equity_valuation(input: &EquityValuationWorkflow) -> WorkflowResult<ValuationResult> {
    let start = std::time::Instant::now();
    
    if input.company.name.is_empty() {
        return WorkflowResult::error(
            "Company name is required".to_string(),
            start.elapsed().as_millis() as u64
        );
    }

    let discount_rate = input.discount_rate.unwrap_or(0.10);
    let terminal_growth = input.terminal_growth.unwrap_or(0.03);

    // Simplified DCF calculation (placeholder)
    let base_value = input.financials.revenue.unwrap_or(1_000_000_000.0) * 5.0;
    let fair_value = base_value / (discount_rate - terminal_growth + 1.0);
    let fair_value_per_share = fair_value / 100_000_000.0;

    let current_price = input.company.market_cap_usd.map(|mc| mc / 100_000_000.0);
    let upside = current_price.map(|cp| ((fair_value_per_share - cp) / cp) * 100.0);

    let mut assumptions = HashMap::new();
    assumptions.insert("discount_rate".to_string(), discount_rate);
    assumptions.insert("terminal_growth".to_string(), terminal_growth);

    // Sensitivity analysis
    let mut sensitivity = Vec::new();
    for dr in [0.08, 0.10, 0.12] {
        for tg in [0.02, 0.03, 0.04] {
            if dr > tg {
                let sv = base_value / (dr - tg + 1.0) / 100_000_000.0;
                sensitivity.push(SensitivityRow {
                    discount_rate: dr,
                    terminal_growth: tg,
                    fair_value: sv,
                });
            }
        }
    }

    let result = ValuationResult {
        company: input.company.name.clone(),
        method: input.method,
        fair_value_per_share,
        current_price,
        upside_percent: upside,
        assumptions,
        sensitivity,
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    WorkflowResult::success(result, start.elapsed().as_millis() as u64)
}

// --- Investment Process Workflows ---

/// Investment pipeline tracking workflow
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PipelineTrackingWorkflow {
    /// Current deals
    pub deals: Vec<InvestmentDeal>,
    /// Update deal stage
    pub update_deal_id: Option<String>,
    /// New stage
    pub new_stage: Option<DealStage>,
}

/// Pipeline summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineSummary {
    /// Deals by stage
    pub deals_by_stage: HashMap<String, Vec<String>>,
    /// Total active deals
    pub total_active: usize,
    /// Total pipeline value (if available)
    pub total_value_usd: Option<f64>,
    /// Deals needing attention
    pub attention_needed: Vec<String>,
    /// Generated at
    pub generated_at: String,
}

/// Run pipeline tracking workflow
pub fn run_pipeline_tracking(input: &PipelineTrackingWorkflow) -> WorkflowResult<PipelineSummary> {
    let start = std::time::Instant::now();
    
    let mut deals_by_stage: HashMap<String, Vec<String>> = HashMap::new();
    let mut total_value = 0.0;
    let mut attention_needed = Vec::new();

    for deal in &input.deals {
        let stage_str = deal.stage.to_string();
        deals_by_stage.entry(stage_str).or_default().push(deal.company.clone());
        
        if let Some(amount) = deal.amount_usd {
            total_value += amount;
        }

        if deal.stage == DealStage::DueDiligence {
            attention_needed.push(format!("{} - DD in progress", deal.company));
        }
    }

    let result = PipelineSummary {
        deals_by_stage,
        total_active: input.deals.len(),
        total_value_usd: if total_value > 0.0 { Some(total_value) } else { None },
        attention_needed,
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    WorkflowResult::success(result, start.elapsed().as_millis() as u64)
}

/// Term sheet generation workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermSheetWorkflow {
    /// Company name
    pub company: String,
    /// Investment amount (USD)
    pub investment_amount: f64,
    /// Pre-money valuation (USD)
    pub pre_money_valuation: f64,
    /// Post-money valuation
    pub post_money_valuation: Option<f64>,
    /// Equity offered (%)
    pub equity_offered: Option<f64>,
    /// Board seats
    pub board_seats: Option<u32>,
    /// Liquidation preference
    pub liquidation_preference: Option<String>,
    /// Anti-dilution protection
    pub anti_dilution: Option<String>,
    /// Other terms
    pub other_terms: Option<HashMap<String, String>>,
}

impl Default for TermSheetWorkflow {
    fn default() -> Self {
        Self {
            company: String::new(),
            investment_amount: 0.0,
            pre_money_valuation: 0.0,
            post_money_valuation: None,
            equity_offered: None,
            board_seats: None,
            liquidation_preference: Some("1x".to_string()),
            anti_dilution: Some("Full ratchet".to_string()),
            other_terms: None,
        }
    }
}

/// Generated term sheet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TermSheet {
    /// Company name
    pub company: String,
    /// Investment amount
    pub investment_amount: f64,
    /// Pre-money valuation
    pub pre_money_valuation: f64,
    /// Post-money valuation
    pub post_money_valuation: f64,
    /// Equity offered (%)
    pub equity_offered: f64,
    /// Price per share
    pub price_per_share: Option<f64>,
    /// Number of shares
    pub num_shares: Option<f64>,
    /// Board composition
    pub board_composition: String,
    /// Key terms
    pub key_terms: HashMap<String, String>,
    /// Generated at
    pub generated_at: String,
}

/// Run term sheet generation workflow
pub fn run_term_sheet(input: &TermSheetWorkflow) -> WorkflowResult<TermSheet> {
    let start = std::time::Instant::now();
    
    if input.company.is_empty() || input.investment_amount <= 0.0 {
        return WorkflowResult::error(
            "Company name and investment amount are required".to_string(),
            start.elapsed().as_millis() as u64
        );
    }

    let post_money = input.post_money_valuation.unwrap_or(
        input.pre_money_valuation + input.investment_amount
    );
    let equity = input.equity_offered.unwrap_or(
        (input.investment_amount / post_money) * 100.0
    );

    let mut key_terms = HashMap::new();
    key_terms.insert("liquidation_preference".to_string(), 
        input.liquidation_preference.clone().unwrap_or_else(|| "1x".to_string()));
    key_terms.insert("anti_dilution".to_string(), 
        input.anti_dilution.clone().unwrap_or_else(|| "Full ratchet".to_string()));
    
    let board_seats = input.board_seats.unwrap_or(1);
    key_terms.insert("board_seats".to_string(), format!("Investor: {}", board_seats));

    let result = TermSheet {
        company: input.company.clone(),
        investment_amount: input.investment_amount,
        pre_money_valuation: input.pre_money_valuation,
        post_money_valuation: post_money,
        equity_offered: equity,
        price_per_share: None,
        num_shares: None,
        board_composition: format!("{} Board Seats", board_seats),
        key_terms,
        generated_at: chrono::Utc::now().to_rfc3339(),
    };

    WorkflowResult::success(result, start.elapsed().as_millis() as u64)
}

// --- Template Registration ---

/// Get all investment workflow templates
pub fn get_templates() -> Vec<TaskTemplate> {
    vec![
        // Market Research
        TaskTemplate {
            id: "inv_market_overview".to_string(),
            name: "Market Overview Report".to_string(),
            description: "Generate comprehensive market overview report with PESTEL analysis".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "market".to_string(), "research".to_string()],
            steps: vec![
                TemplateStep {
                    order: 1,
                    description: "Collect industry data".to_string(),
                    command: "python".to_string(),
                    args: vec!["scripts/market_research.py".to_string(), "--industry".to_string(), "{{industry}}".to_string()],
                    working_dir: None,
                    timeout_secs: 300,
                    abort_on_failure: true,
                    optional: false,
                },
            ],
            params: vec![
                TemplateParam {
                    name: "industry".to_string(),
                    description: "Industry to analyze".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["Technology".to_string(), "Healthcare".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_competitor_financial".to_string(),
            name: "Competitor Financial Analysis".to_string(),
            description: "Extract and compare financial metrics from competitor disclosures".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "financial".to_string(), "competitor".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "companies".to_string(),
                    description: "Comma-separated company tickers".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["AAPL,GOOGL,MSFT".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_industry_trend".to_string(),
            name: "Industry Trend Analysis".to_string(),
            description: "Analyze news and reports for industry trend visualization".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "trends".to_string(), "analysis".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 1200,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_macro_indicator".to_string(),
            name: "Macro Economic Indicator Monitor".to_string(),
            description: "Monitor GDP, interest rates, and forex indicators in real-time".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "macro".to_string(), "monitoring".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        // Due Diligence
        TaskTemplate {
            id: "inv_dd_company".to_string(),
            name: "Company Due Diligence".to_string(),
            description: "Comprehensive company due diligence with financial/legal/technical analysis".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "invest:write".to_string(),
            tags: vec!["investment".to_string(), "dd".to_string(), "due_diligence".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "company".to_string(),
                    description: "Target company name".to_string(),
                    default: None,
                    required: true,
                    examples: vec![],
                },
            ],
            platforms: vec![],
            estimated_secs: 1800,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_dd_tech".to_string(),
            name: "Technical Due Diligence".to_string(),
            description: "Technology stack and patent analysis for investment decisions".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "tech".to_string(), "dd".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 1200,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_dd_financial".to_string(),
            name: "Financial Due Diligence".to_string(),
            description: "Financial statement anomaly detection and growth analysis".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "financial".to_string(), "dd".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 900,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_dd_legal".to_string(),
            name: "Legal Due Diligence".to_string(),
            description: "Contract and litigation risk assessment".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "invest:write".to_string(),
            tags: vec!["investment".to_string(), "legal".to_string(), "dd".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        // Portfolio Management (already implemented in workflow functions)
        TaskTemplate {
            id: "inv_performance_report".to_string(),
            name: "Performance Report".to_string(),
            description: "Generate portfolio performance report with benchmark comparison".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "portfolio:read".to_string(),
            tags: vec!["investment".to_string(), "performance".to_string(), "report".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 480,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_dividend_tracker".to_string(),
            name: "Dividend Tracker".to_string(),
            description: "Track dividend calendar and expected receipts".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "portfolio:read".to_string(),
            tags: vec!["investment".to_string(), "dividend".to_string(), "tracker".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 180,
            builtin: true,
        },
        // Investment Analysis
        TaskTemplate {
            id: "inv_tech_analysis".to_string(),
            name: "Technical Analysis".to_string(),
            description: "Chart patterns and technical indicators for trading signals".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "technical".to_string(), "analysis".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "ticker".to_string(),
                    description: "Stock ticker symbol".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["AAPL".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 480,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_sentiment_analysis".to_string(),
            name: "Sentiment Analysis".to_string(),
            description: "Analyze news and social media sentiment for investment strategy".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "sentiment".to_string(), "nlp".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_ml_prediction".to_string(),
            name: "ML-based Prediction".to_string(),
            description: "Forecast using machine learning models with historical data".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "ml".to_string(), "prediction".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 900,
            builtin: true,
        },
        // Investment Process
        TaskTemplate {
            id: "inv_meeting_summary".to_string(),
            name: "Meeting Summary".to_string(),
            description: "Extract key points from investment meeting notes".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "meeting".to_string(), "summary".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 300,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_portfolio_dashboard".to_string(),
            name: "Portfolio Dashboard".to_string(),
            description: "Real-time portfolio dashboard update with live data".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Viewer,
            capability: "portfolio:read".to_string(),
            tags: vec!["investment".to_string(), "dashboard".to_string(), "realtime".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 120,
            builtin: true,
        },
        // Existing templates
        TaskTemplate {
            id: "inv_portfolio_rebalance".to_string(),
            name: "Portfolio Rebalancing".to_string(),
            description: "Calculate and recommend portfolio rebalancing based on target allocation".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "portfolio:write".to_string(),
            tags: vec!["investment".to_string(), "portfolio".to_string(), "rebalancing".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 300,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_equity_valuation".to_string(),
            name: "Equity Valuation (DCF)".to_string(),
            description: "Calculate fair value using Discounted Cash Flow method".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "valuation".to_string(), "dcf".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "company".to_string(),
                    description: "Company name or ticker".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["AAPL".to_string(), "Tesla".to_string()],
                },
                TemplateParam {
                    name: "discount_rate".to_string(),
                    description: "WACC/Discount rate".to_string(),
                    default: Some("0.10".to_string()),
                    required: false,
                    examples: vec!["0.08".to_string(), "0.12".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 720,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_risk_report".to_string(),
            name: "Portfolio Risk Report".to_string(),
            description: "Generate risk analysis including VaR, volatility, and recommendations".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "portfolio:read".to_string(),
            tags: vec!["investment".to_string(), "risk".to_string(), "var".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 600,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_pipeline_tracking".to_string(),
            name: "Investment Pipeline Tracking".to_string(),
            description: "Track and visualize investment deal pipeline stages".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Operator,
            capability: "invest:read".to_string(),
            tags: vec!["investment".to_string(), "pipeline".to_string(), "deals".to_string()],
            steps: vec![],
            params: vec![],
            platforms: vec![],
            estimated_secs: 60,
            builtin: true,
        },
        TaskTemplate {
            id: "inv_term_sheet_gen".to_string(),
            name: "Term Sheet Generation".to_string(),
            description: "Generate standard term sheet from investment conditions".to_string(),
            category: TemplateCategory::Custom,
            required_role: RequiredRole::Admin,
            capability: "invest:write".to_string(),
            tags: vec!["investment".to_string(), "term_sheet".to_string(), "legal".to_string()],
            steps: vec![],
            params: vec![
                TemplateParam {
                    name: "company".to_string(),
                    description: "Target company name".to_string(),
                    default: None,
                    required: true,
                    examples: vec![],
                },
                TemplateParam {
                    name: "amount".to_string(),
                    description: "Investment amount (USD)".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["1000000".to_string()],
                },
                TemplateParam {
                    name: "valuation".to_string(),
                    description: "Pre-money valuation (USD)".to_string(),
                    default: None,
                    required: true,
                    examples: vec!["10000000".to_string()],
                },
            ],
            platforms: vec![],
            estimated_secs: 180,
            builtin: true,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portfolio_rebalance() {
        let workflow = PortfolioRebalanceWorkflow {
            positions: vec![
                PortfolioPosition {
                    ticker: "AAPL".to_string(),
                    shares: 100.0,
                    avg_cost: 150.0,
                    current_price: 180.0,
                    target_allocation: 40.0,
                },
                PortfolioPosition {
                    ticker: "GOOGL".to_string(),
                    shares: 50.0,
                    avg_cost: 2500.0,
                    current_price: 2800.0,
                    target_allocation: 40.0,
                },
                PortfolioPosition {
                    ticker: "MSFT".to_string(),
                    shares: 80.0,
                    avg_cost: 300.0,
                    current_price: 380.0,
                    target_allocation: 20.0,
                },
            ],
            target_allocation: [
                ("AAPL".to_string(), 40.0),
                ("GOOGL".to_string(), 40.0),
                ("MSFT".to_string(), 20.0),
            ].into_iter().collect(),
            cash_available: 0.0,
            threshold_percent: Some(5.0),
        };

        let result = run_portfolio_rebalance(&workflow);
        assert!(result.success);
        let data = result.data.unwrap();
        assert!(!data.recommendations.is_empty());
        println!("Recommendations: {:?}", data.recommendations);
    }

    #[test]
    fn test_equity_valuation() {
        let workflow = EquityValuationWorkflow {
            company: CompanyProfile {
                name: "Test Corp".to_string(),
                ticker: Some("TEST".to_string()),
                sector: "Technology".to_string(),
                market_cap_usd: Some(50_000_000_000.0),
                products: vec!["Software".to_string()],
                competitors: vec![],
            },
            financials: CompanyFinancials {
                name: "Test Corp".to_string(),
                revenue: Some(100_000_000_000.0),
                net_income: Some(20_000_000_000.0),
                ebitda: Some(30_000_000_000.0),
                pe_ratio: Some(25.0),
                debt_equity: Some(0.5),
                roe: Some(0.2),
            },
            method: ValuationMethod::Dcf,
            discount_rate: Some(0.10),
            terminal_growth: Some(0.03),
        };

        let result = run_equity_valuation(&workflow);
        assert!(result.success);
        let data = result.data.unwrap();
        println!("Fair value per share: ${:.2}", data.fair_value_per_share);
    }

    #[test]
    fn test_term_sheet_generation() {
        let workflow = TermSheetWorkflow {
            company: "StartupXYZ".to_string(),
            investment_amount: 5_000_000.0,
            pre_money_valuation: 20_000_000.0,
            post_money_valuation: None,
            equity_offered: None,
            board_seats: Some(1),
            liquidation_preference: Some("1x".to_string()),
            anti_dilution: Some("Full ratchet".to_string()),
            other_terms: None,
        };

        let result = run_term_sheet(&workflow);
        assert!(result.success);
        let data = result.data.unwrap();
        println!("Post-money valuation: ${:.0}", data.post_money_valuation);
    }

    #[test]
    fn test_pipeline_tracking() {
        let workflow = PipelineTrackingWorkflow {
            deals: vec![
                InvestmentDeal {
                    deal_id: "D001".to_string(),
                    company: "Company A".to_string(),
                    stage: DealStage::DueDiligence,
                    amount_usd: Some(5_000_000.0),
                    date: "2026-01-15".to_string(),
                    notes: None,
                },
                InvestmentDeal {
                    deal_id: "D002".to_string(),
                    company: "Company B".to_string(),
                    stage: DealStage::TermSheet,
                    amount_usd: Some(3_000_000.0),
                    date: "2026-02-01".to_string(),
                    notes: None,
                },
            ],
            update_deal_id: None,
            new_stage: None,
        };

        let result = run_pipeline_tracking(&workflow);
        assert!(result.success);
        let data = result.data.unwrap();
        println!("Total active deals: {}", data.total_active);
    }
}
