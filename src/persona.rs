//! AgentPersona — defines an agent's personality, specialization, and communication style.
//!
//! The Persona system drives:
//! - System prompt injection via BootRitual
//! - Delegation routing (specialization-based matching)
//! - Lesson-based specialization auto-calculation

use serde::{Deserialize, Serialize};

// ─── Enums ─────────────────────────────────────────────────────────────────────

/// Built-in persona presets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersonaPreset {
    Analyst,
    Creator,
    Executor,
    Guardian,
    Mentor,
    Custom,
}

impl PersonaPreset {
    /// Human-readable name
    pub fn label(&self) -> &'static str {
        match self {
            PersonaPreset::Analyst => "Analyst",
            PersonaPreset::Creator => "Creator",
            PersonaPreset::Executor => "Executor",
            PersonaPreset::Guardian => "Guardian",
            PersonaPreset::Mentor => "Mentor",
            PersonaPreset::Custom => "Custom",
        }
    }

    /// Default traits for the preset
    pub fn default_traits(&self) -> PersonaTraits {
        match self {
            PersonaPreset::Analyst => PersonaTraits {
                caution: 0.8,
                creativity: 0.4,
                autonomy: 0.5,
                verbosity: 0.7,
            },
            PersonaPreset::Creator => PersonaTraits {
                caution: 0.3,
                creativity: 0.9,
                autonomy: 0.7,
                verbosity: 0.6,
            },
            PersonaPreset::Executor => PersonaTraits {
                caution: 0.5,
                creativity: 0.5,
                autonomy: 0.9,
                verbosity: 0.3,
            },
            PersonaPreset::Guardian => PersonaTraits {
                caution: 0.95,
                creativity: 0.2,
                autonomy: 0.4,
                verbosity: 0.5,
            },
            PersonaPreset::Mentor => PersonaTraits {
                caution: 0.6,
                creativity: 0.6,
                autonomy: 0.6,
                verbosity: 0.9,
            },
            PersonaPreset::Custom => PersonaTraits::default(),
        }
    }
}

impl std::fmt::Display for PersonaPreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─── PersonaTraits ─────────────────────────────────────────────────────────────

/// Personality trait scalars (0.0 to 1.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaTraits {
    /// Risk aversion: 0 = reckless, 1 = extremely cautious
    pub caution: f64,
    /// Creative problem‐solving preference: 0 = rigid, 1 = highly innovative
    pub creativity: f64,
    /// Autonomy preference: 0 = always ask, 1 = fully autonomous
    pub autonomy: f64,
    /// Communication verbosity: 0 = terse, 1 = very detailed
    pub verbosity: f64,
}

impl Default for PersonaTraits {
    fn default() -> Self {
        Self {
            caution: 0.5,
            creativity: 0.5,
            autonomy: 0.5,
            verbosity: 0.5,
        }
    }
}

impl PersonaTraits {
    /// Convert traits to system-prompt directive lines
    pub fn to_prompt_directives(&self) -> Vec<String> {
        let mut directives = Vec::new();

        if self.caution >= 0.8 {
            directives.push(
                "Always double-check before taking irreversible actions. Prefer safe defaults."
                    .to_string(),
            );
        } else if self.caution <= 0.2 {
            directives.push("Proceed decisively. Avoid unnecessary confirmations.".to_string());
        }

        if self.creativity >= 0.8 {
            directives
                .push("Explore novel approaches and suggest creative alternatives.".to_string());
        }

        if self.autonomy >= 0.8 {
            directives
                .push("Execute tasks autonomously. Only escalate critical ambiguities.".to_string());
        } else if self.autonomy <= 0.3 {
            directives
                .push("Ask for confirmation before each significant step.".to_string());
        }

        if self.verbosity >= 0.8 {
            directives.push(
                "Provide detailed explanations and reasoning for every decision.".to_string(),
            );
        } else if self.verbosity <= 0.2 {
            directives.push("Be concise. Avoid unnecessary elaboration.".to_string());
        }

        directives
    }
}

// ─── Specialization ────────────────────────────────────────────────────────────

/// A domain specialization with confidence level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Specialization {
    pub domain: String,
    pub confidence: f64, // 0.0 to 1.0
    pub completed_tasks: u32,
    pub lessons_applied: u32,
}

impl Specialization {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            confidence: 0.0,
            completed_tasks: 0,
            lessons_applied: 0,
        }
    }

    /// Recalculate confidence from completed tasks and lessons.
    /// Formula: min(1.0, (tasks * 0.05) + (lessons * 0.1))
    pub fn recalculate_confidence(&mut self) {
        self.confidence =
            (self.completed_tasks as f64 * 0.05 + self.lessons_applied as f64 * 0.1).min(1.0);
    }
}

// ─── AgentPersona ─────────────────────────────────────────────────────────────

/// Full persona definition for an EdgeClaw agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPersona {
    pub name: String,
    pub avatar: String, // emoji or URL
    pub preset: PersonaPreset,
    pub traits: PersonaTraits,
    pub specializations: Vec<Specialization>,
    pub communication_style: String,
}

impl AgentPersona {
    /// Create a persona from a preset
    pub fn from_preset(name: &str, preset: PersonaPreset) -> Self {
        let traits = preset.default_traits();
        let communication_style = match preset {
            PersonaPreset::Analyst => "Structured, data-driven, methodical.".to_string(),
            PersonaPreset::Creator => "Enthusiastic, idea-focused, expressive.".to_string(),
            PersonaPreset::Executor => "Direct, action-oriented, concise.".to_string(),
            PersonaPreset::Guardian => "Careful, thorough, security-conscious.".to_string(),
            PersonaPreset::Mentor => "Patient, explanatory, supportive.".to_string(),
            PersonaPreset::Custom => "Balanced and adaptive.".to_string(),
        };

        Self {
            name: name.to_string(),
            avatar: match preset {
                PersonaPreset::Analyst => "📊",
                PersonaPreset::Creator => "🎨",
                PersonaPreset::Executor => "⚡",
                PersonaPreset::Guardian => "🛡️",
                PersonaPreset::Mentor => "🎓",
                PersonaPreset::Custom => "🤖",
            }
            .to_string(),
            preset,
            traits,
            specializations: Vec::new(),
            communication_style,
        }
    }

    /// Generate a system-prompt injection block from the persona
    pub fn to_system_prompt(&self) -> String {
        let mut prompt = format!(
            "=== AGENT PERSONA: {} ({}) ===\n",
            self.name,
            self.preset.label()
        );
        prompt.push_str(&format!("Communication Style: {}\n", self.communication_style));
        prompt.push_str("\nBehavioural Directives:\n");

        let directives = self.traits.to_prompt_directives();
        if directives.is_empty() {
            prompt.push_str("- Balanced and contextual approach.\n");
        } else {
            for d in &directives {
                prompt.push_str(&format!("- {d}\n"));
            }
        }

        if !self.specializations.is_empty() {
            prompt.push_str("\nSpecialization Areas:\n");
            for spec in &self.specializations {
                if spec.confidence > 0.0 {
                    prompt.push_str(&format!(
                        "- {} (confidence: {:.0}%)\n",
                        spec.domain,
                        spec.confidence * 100.0
                    ));
                }
            }
        }

        prompt
    }

    /// Add or update a specialization domain
    pub fn add_specialization(&mut self, domain: &str) {
        if !self
            .specializations
            .iter()
            .any(|s| s.domain.eq_ignore_ascii_case(domain))
        {
            self.specializations.push(Specialization::new(domain));
        }
    }

    /// Record a completed task in a domain and recalculate confidence
    pub fn record_task_completion(&mut self, domain: &str) {
        if let Some(spec) = self
            .specializations
            .iter_mut()
            .find(|s| s.domain.eq_ignore_ascii_case(domain))
        {
            spec.completed_tasks += 1;
            spec.recalculate_confidence();
        } else {
            // Auto-create if not exists
            let mut spec = Specialization::new(domain);
            spec.completed_tasks = 1;
            spec.recalculate_confidence();
            self.specializations.push(spec);
        }
    }

    /// Record a lesson applied in a domain and recalculate confidence
    pub fn record_lesson_applied(&mut self, domain: &str) {
        if let Some(spec) = self
            .specializations
            .iter_mut()
            .find(|s| s.domain.eq_ignore_ascii_case(domain))
        {
            spec.lessons_applied += 1;
            spec.recalculate_confidence();
        } else {
            let mut spec = Specialization::new(domain);
            spec.lessons_applied = 1;
            spec.recalculate_confidence();
            self.specializations.push(spec);
        }
    }

    /// Get the top N specializations by confidence
    pub fn top_specializations(&self, n: usize) -> Vec<&Specialization> {
        let mut specs: Vec<&Specialization> = self.specializations.iter().collect();
        specs.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        specs.into_iter().take(n).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preset_labels() {
        assert_eq!(PersonaPreset::Analyst.label(), "Analyst");
        assert_eq!(PersonaPreset::Guardian.label(), "Guardian");
        assert_eq!(PersonaPreset::Creator.label(), "Creator");
        assert_eq!(PersonaPreset::Executor.label(), "Executor");
        assert_eq!(PersonaPreset::Mentor.label(), "Mentor");
        assert_eq!(PersonaPreset::Custom.label(), "Custom");
    }

    #[test]
    fn test_preset_display() {
        let s = format!("{}", PersonaPreset::Analyst);
        assert_eq!(s, "Analyst");
    }

    #[test]
    fn test_guardian_has_high_caution() {
        let traits = PersonaPreset::Guardian.default_traits();
        assert!(traits.caution >= 0.9);
    }

    #[test]
    fn test_creator_has_high_creativity() {
        let traits = PersonaPreset::Creator.default_traits();
        assert!(traits.creativity >= 0.8);
    }

    #[test]
    fn test_executor_has_high_autonomy() {
        let traits = PersonaPreset::Executor.default_traits();
        assert!(traits.autonomy >= 0.8);
    }

    #[test]
    fn test_mentor_has_high_verbosity() {
        let traits = PersonaPreset::Mentor.default_traits();
        assert!(traits.verbosity >= 0.8);
    }

    #[test]
    fn test_traits_prompt_directives_caution() {
        let traits = PersonaTraits {
            caution: 0.9,
            creativity: 0.5,
            autonomy: 0.5,
            verbosity: 0.5,
        };
        let directives = traits.to_prompt_directives();
        assert!(directives.iter().any(|d| d.contains("double-check")));
    }

    #[test]
    fn test_traits_prompt_directives_autonomy() {
        let traits = PersonaTraits {
            caution: 0.5,
            creativity: 0.5,
            autonomy: 0.9,
            verbosity: 0.5,
        };
        let directives = traits.to_prompt_directives();
        assert!(directives.iter().any(|d| d.contains("autonomously")));
    }

    #[test]
    fn test_specialization_confidence_formula() {
        let mut spec = Specialization::new("rust");
        spec.completed_tasks = 10; // 10 * 0.05 = 0.5
        spec.lessons_applied = 3;  // 3 * 0.1 = 0.3 → total 0.8
        spec.recalculate_confidence();
        assert!((spec.confidence - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_specialization_confidence_capped_at_1() {
        let mut spec = Specialization::new("python");
        spec.completed_tasks = 100;
        spec.lessons_applied = 100;
        spec.recalculate_confidence();
        assert_eq!(spec.confidence, 1.0);
    }

    #[test]
    fn test_persona_from_preset_analyst() {
        let persona = AgentPersona::from_preset("DataBot", PersonaPreset::Analyst);
        assert_eq!(persona.preset, PersonaPreset::Analyst);
        assert!(persona.avatar == "📊");
        assert!(persona.communication_style.contains("data-driven"));
    }

    #[test]
    fn test_persona_record_task_completion() {
        let mut persona = AgentPersona::from_preset("Alpha", PersonaPreset::Executor);
        persona.record_task_completion("devops");
        persona.record_task_completion("devops");

        let spec = persona
            .specializations
            .iter()
            .find(|s| s.domain == "devops")
            .unwrap();
        assert_eq!(spec.completed_tasks, 2);
        // 2 * 0.05 = 0.1
        assert!((spec.confidence - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_persona_record_lesson_applied() {
        let mut persona = AgentPersona::from_preset("Alpha", PersonaPreset::Executor);
        persona.record_lesson_applied("rust");

        let spec = persona
            .specializations
            .iter()
            .find(|s| s.domain == "rust")
            .unwrap();
        assert_eq!(spec.lessons_applied, 1);
        assert!((spec.confidence - 0.1).abs() < 0.001);
    }

    #[test]
    fn test_top_specializations() {
        let mut persona = AgentPersona::from_preset("Beta", PersonaPreset::Creator);
        for _ in 0..10 {
            persona.record_task_completion("python");
        }
        for _ in 0..3 {
            persona.record_task_completion("rust");
        }

        let top = persona.top_specializations(1);
        assert_eq!(top[0].domain, "python");
    }

    #[test]
    fn test_to_system_prompt_contains_persona() {
        let persona = AgentPersona::from_preset("GuardBot", PersonaPreset::Guardian);
        let prompt = persona.to_system_prompt();
        assert!(prompt.contains("GuardBot"));
        assert!(prompt.contains("Guardian"));
        assert!(prompt.contains("double-check")); // caution >= 0.8
    }
}
