//! Intent Understanding Engine
//!
//! Converts natural language input into structured business intents.
//! This module provides pattern-based intent classification.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ─── Error Types ─────────────────────────────────────────────────────────────

#[derive(Error, Debug)]
pub enum IntentError {
    #[error("Classification failed: {0}")]
    ClassificationError(String),
    #[error("Template matching failed: {0}")]
    TemplateMatchError(String),
}

pub type Result<T> = std::result::Result<T, IntentError>;

// ─── Intent Types ─────────────────────────────────────────────────────────

/// High-level business intent categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentType {
    ReportGeneration,
    DataAnalysis,
    Scheduling,
    EmailAutomation,
    FileOrganization,
    WebResearch,
    CiCdPipeline,
    CodeReview,
    Deployment,
    ContentCreation,
    SocialMedia,
    InvestmentAnalysis,
    DueDiligence,
    PortfolioManagement,
    AutomationSetup,
    Unknown,
}

impl IntentType {
    /// Get all supported intent types
    pub fn all() -> Vec<Self> {
        vec![
            Self::ReportGeneration,
            Self::DataAnalysis,
            Self::Scheduling,
            Self::EmailAutomation,
            Self::FileOrganization,
            Self::WebResearch,
            Self::CiCdPipeline,
            Self::CodeReview,
            Self::Deployment,
            Self::ContentCreation,
            Self::SocialMedia,
            Self::InvestmentAnalysis,
            Self::DueDiligence,
            Self::PortfolioManagement,
            Self::AutomationSetup,
        ]
    }

    /// Get domain category
    pub fn domain(&self) -> &'static str {
        match self {
            Self::ReportGeneration | Self::DataAnalysis | Self::Scheduling | Self::EmailAutomation => "business",
            Self::CiCdPipeline | Self::CodeReview | Self::Deployment => "development",
            Self::ContentCreation | Self::SocialMedia => "marketing",
            Self::InvestmentAnalysis | Self::DueDiligence | Self::PortfolioManagement => "investment",
            Self::FileOrganization | Self::WebResearch | Self::AutomationSetup | Self::Unknown => "custom",
        }
    }
}

impl std::fmt::Display for IntentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntentType::ReportGeneration => write!(f, "Report Generation"),
            IntentType::DataAnalysis => write!(f, "Data Analysis"),
            IntentType::Scheduling => write!(f, "Scheduling"),
            IntentType::EmailAutomation => write!(f, "Email Automation"),
            IntentType::FileOrganization => write!(f, "File Organization"),
            IntentType::WebResearch => write!(f, "Web Research"),
            IntentType::CiCdPipeline => write!(f, "CI/CD Pipeline"),
            IntentType::CodeReview => write!(f, "Code Review"),
            IntentType::Deployment => write!(f, "Deployment"),
            IntentType::ContentCreation => write!(f, "Content Creation"),
            IntentType::SocialMedia => write!(f, "Social Media"),
            IntentType::InvestmentAnalysis => write!(f, "Investment Analysis"),
            IntentType::DueDiligence => write!(f, "Due Diligence"),
            IntentType::PortfolioManagement => write!(f, "Portfolio Management"),
            IntentType::AutomationSetup => write!(f, "Automation Setup"),
            IntentType::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─── Entity Types ─────────────────────────────────────────────────────────

/// Extracted entities from user input
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtractedEntities {
    #[serde(default)]
    pub time_entities: Vec<TimeEntity>,
    #[serde(default)]
    pub numbers: Vec<NumberEntity>,
    #[serde(default)]
    pub organizations: Vec<String>,
    #[serde(default)]
    pub custom: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeEntity {
    pub value: String,
    pub normalized: String,
    pub entity_type: TimeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeType {
    Date,
    DateRange,
    Duration,
    Frequency,
    TimeOfDay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NumberEntity {
    pub value: f64,
    pub raw: String,
    pub unit: Option<String>,
}

// ─── Intent Structure ─────────────────────────────────────────────────────

/// Complete structured intent from user input
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Intent {
    pub intent_type: IntentType,
    pub confidence: f32,
    pub entities: ExtractedEntities,
    pub raw_input: String,
    pub goal: String,
    pub suggested_templates: Vec<String>,
    pub missing_params: Vec<MissingParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissingParam {
    pub name: String,
    pub description: String,
    pub param_type: String,
}

// ─── User Context ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserContext {
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub preferences: UserPreferences,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserPreferences {
    pub language: String,
    pub timezone: String,
}

// ─── Intent Engine ────────────────────────────────────────────────────────

/// Intent Understanding Engine - simplified version
pub struct IntentEngine {
    patterns: Vec<(IntentType, Vec<&'static str>)>,
}

impl IntentEngine {
    /// Create a new intent engine
    pub fn new() -> Self {
        let patterns = vec![
            // Report Generation
            (IntentType::ReportGeneration, vec![
                "보고서", "리포트", "report", "분석 보고", "주간", "월간", "분기별"
            ]),
            // Data Analysis
            (IntentType::DataAnalysis, vec![
                "분석", "analysis", "데이터", "analytics", "통계"
            ]),
            // Scheduling
            (IntentType::Scheduling, vec![
                "일정", "캘린더", "schedule", "meeting", "회의", "예약"
            ]),
            // Email
            (IntentType::EmailAutomation, vec![
                "이메일", "email", "메일", "편지"
            ]),
            // Deployment
            (IntentType::Deployment, vec![
                "production", "릴리스", "deploy"
            ]),
            // CI/CD
            (IntentType::CiCdPipeline, vec![
                "ci", "cd", "pipeline", "파이프라인", "빌드", "배포"
            ]),
            // Content Creation
            (IntentType::ContentCreation, vec![
                "글", "content", "블로그", "post", "작성"
            ]),
            // Investment
            (IntentType::InvestmentAnalysis, vec![
                "투자", "investment", "시장", "market", "포트폴리오", "portfolio"
            ]),
        ];
        
        Self { patterns }
    }
    
    /// Understand user input and return structured intent
    pub fn understand(&self, input: &str, _context: &UserContext) -> Result<Intent> {
        let intent_type = self.classify_intent(input);
        let entities = self.extract_entities(input);
        let goal = format!("{} - {}", intent_type, input);
        let suggested_templates = self.match_templates(&intent_type);
        let missing_params = self.find_missing_params(&suggested_templates, &entities);
        
        Ok(Intent {
            intent_type,
            confidence: 0.85,
            entities,
            raw_input: input.to_string(),
            goal,
            suggested_templates,
            missing_params,
        })
    }
    
    /// Classify input into intent type
    fn classify_intent(&self, input: &str) -> IntentType {
        let input_lower = input.to_lowercase();
        let mut best_match = IntentType::Unknown;
        let mut best_score = 0;
        
        for (intent_type, keywords) in &self.patterns {
            let mut score = 0;
            for keyword in keywords {
                if input_lower.contains(&keyword.to_lowercase()) {
                    score += 1;
                }
            }
            
            if score > best_score {
                best_score = score;
                best_match = *intent_type;
            }
        }
        
        if best_match == IntentType::Unknown {
            best_match = IntentType::AutomationSetup;
        }
        
        best_match
    }
    
    /// Extract entities from input
    fn extract_entities(&self, input: &str) -> ExtractedEntities {
        let mut entities = ExtractedEntities::default();
        
        // Extract time entities
        let time_keywords = ["주간", "월간", "분기", "오늘", "어제", "내일", "이번주", "이번달"];
        for keyword in time_keywords {
            if input.contains(keyword) {
                entities.time_entities.push(TimeEntity {
                    value: keyword.to_string(),
                    normalized: keyword.to_string(),
                    entity_type: TimeType::DateRange,
                });
            }
        }
        
        // Extract numbers
        for word in input.split_whitespace() {
            if let Ok(num) = word.parse::<f64>() {
                entities.numbers.push(NumberEntity {
                    value: num,
                    raw: word.to_string(),
                    unit: None,
                });
            }
        }
        
        entities
    }
    
    /// Match intents to workflow templates
    fn match_templates(&self, intent_type: &IntentType) -> Vec<String> {
        match intent_type {
            IntentType::ReportGeneration => vec![
                "biz_weekly_sales".to_string(),
                "biz_monthly_finance".to_string(),
            ],
            IntentType::CiCdPipeline => vec![
                "dev_ci_pipeline".to_string(),
                "dev_cd_deploy".to_string(),
            ],
            IntentType::ContentCreation => vec![
                "mkt_blog_post".to_string(),
            ],
            IntentType::InvestmentAnalysis => vec![
                "inv_market_overview".to_string(),
            ],
            _ => vec![],
        }
    }
    
    /// Find missing parameters
    fn find_missing_params(&self, templates: &[String], entities: &ExtractedEntities) -> Vec<MissingParam> {
        let mut missing = Vec::new();
        
        if !templates.is_empty() && entities.time_entities.is_empty() {
            missing.push(MissingParam {
                name: "report_period".to_string(),
                description: "보고 기간을 지정해주세요".to_string(),
                param_type: "enum".to_string(),
            });
        }
        
        missing
    }
}

impl Default for IntentEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps intents to workflow templates
pub struct TemplateMatcher;

impl TemplateMatcher {
    /// Find best matching template for an intent
    pub fn find_best_match(intent: &Intent, available_templates: &[String]) -> Option<String> {
        for template_id in &intent.suggested_templates {
            if available_templates.contains(template_id) {
                return Some(template_id.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_intent_classification() {
        let engine = IntentEngine::new();
        let context = UserContext::default();
        
        let intent = engine.understand("주간 판매보고서 만들어줘", &context).unwrap();
        assert_eq!(intent.intent_type, IntentType::ReportGeneration);
        
        let intent = engine.understand("Deploy to production", &context).unwrap();
        assert_eq!(intent.intent_type, IntentType::Deployment);
    }
}
