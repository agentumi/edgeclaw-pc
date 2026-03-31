//! # P2-18: Cron-based Task Scheduler
//!
//! Periodically executes workflow templates based on cron expressions.
//! Integrates with `workflow_engine.rs` DAG executor for task execution.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A cron-style schedule expression (simplified: minute hour day_of_month month day_of_week)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronExpression {
    /// Minutes (0-59) or * for every minute
    pub minute: CronField,
    /// Hours (0-23) or * for every hour
    pub hour: CronField,
    /// Day of month (1-31) or * for every day
    pub day_of_month: CronField,
    /// Month (1-12) or * for every month
    pub month: CronField,
    /// Day of week (0-6, 0=Sunday) or * for every day
    pub day_of_week: CronField,
}

/// A single cron field value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CronField {
    /// Match any value
    Any,
    /// Match a specific value
    Exact(u32),
    /// Match a range (inclusive)
    Range(u32, u32),
    /// Match specific values
    List(Vec<u32>),
    /// Match every N units (step)
    Step(u32),
}

impl CronField {
    /// Check if a value matches this field
    pub fn matches(&self, value: u32) -> bool {
        match self {
            CronField::Any => true,
            CronField::Exact(v) => *v == value,
            CronField::Range(start, end) => value >= *start && value <= *end,
            CronField::List(values) => values.contains(&value),
            CronField::Step(step) => *step > 0 && value.is_multiple_of(*step),
        }
    }
}

impl CronExpression {
    /// Parse a cron string ("* * * * *" format)
    pub fn parse(expr: &str) -> Result<Self, String> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(format!(
                "Invalid cron expression '{}': expected 5 fields (min hour dom month dow)",
                expr
            ));
        }

        Ok(Self {
            minute: Self::parse_field(parts[0], 0, 59)?,
            hour: Self::parse_field(parts[1], 0, 23)?,
            day_of_month: Self::parse_field(parts[2], 1, 31)?,
            month: Self::parse_field(parts[3], 1, 12)?,
            day_of_week: Self::parse_field(parts[4], 0, 6)?,
        })
    }

    fn parse_field(field: &str, _min: u32, _max: u32) -> Result<CronField, String> {
        if field == "*" {
            return Ok(CronField::Any);
        }

        // Step: */5
        if let Some(step_str) = field.strip_prefix("*/") {
            let step: u32 = step_str
                .parse()
                .map_err(|_| format!("Invalid step: {}", field))?;
            return Ok(CronField::Step(step));
        }

        // Range: 1-5
        if field.contains('-') {
            let parts: Vec<&str> = field.split('-').collect();
            if parts.len() == 2 {
                let start: u32 = parts[0]
                    .parse()
                    .map_err(|_| format!("Invalid range start: {}", field))?;
                let end: u32 = parts[1]
                    .parse()
                    .map_err(|_| format!("Invalid range end: {}", field))?;
                return Ok(CronField::Range(start, end));
            }
        }

        // List: 1,3,5
        if field.contains(',') {
            let values: Result<Vec<u32>, _> = field.split(',').map(|v| v.parse()).collect();
            return Ok(CronField::List(
                values.map_err(|_| format!("Invalid list: {}", field))?,
            ));
        }

        // Exact value
        let val: u32 = field
            .parse()
            .map_err(|_| format!("Invalid cron field: {}", field))?;
        Ok(CronField::Exact(val))
    }

    /// Check if the given timestamp matches this cron expression
    pub fn matches(&self, dt: &DateTime<Utc>) -> bool {
        self.minute.matches(dt.minute())
            && self.hour.matches(dt.hour())
            && self.day_of_month.matches(dt.day())
            && self.month.matches(dt.month())
            && self
                .day_of_week
                .matches(dt.weekday().num_days_from_sunday())
    }
}

/// A scheduled job that links a cron expression to a workflow template
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledJob {
    pub id: String,
    pub name: String,
    pub cron_expr: String,
    pub template_id: String,
    pub enabled: bool,
    pub last_run: Option<String>,
    pub next_run: Option<String>,
    pub run_count: u32,
    pub max_runs: Option<u32>,
    pub created_at: String,
}

/// Cron scheduler that manages periodic job execution
pub struct CronScheduler {
    jobs: HashMap<String, ScheduledJob>,
    parsed_crons: HashMap<String, CronExpression>,
}

impl Default for CronScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl CronScheduler {
    /// Create a new empty scheduler
    pub fn new() -> Self {
        Self {
            jobs: HashMap::new(),
            parsed_crons: HashMap::new(),
        }
    }

    /// Register a new scheduled job
    pub fn add_job(
        &mut self,
        name: &str,
        cron_expr: &str,
        template_id: &str,
    ) -> Result<ScheduledJob, String> {
        let parsed = CronExpression::parse(cron_expr)?;
        let id = format!(
            "sched_{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );

        let job = ScheduledJob {
            id: id.clone(),
            name: name.to_string(),
            cron_expr: cron_expr.to_string(),
            template_id: template_id.to_string(),
            enabled: true,
            last_run: None,
            next_run: None,
            run_count: 0,
            max_runs: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        self.parsed_crons.insert(id.clone(), parsed);
        self.jobs.insert(id, job.clone());
        Ok(job)
    }

    /// Remove a scheduled job
    pub fn remove_job(&mut self, job_id: &str) -> bool {
        self.parsed_crons.remove(job_id);
        self.jobs.remove(job_id).is_some()
    }

    /// Enable or disable a job
    pub fn set_enabled(&mut self, job_id: &str, enabled: bool) -> Result<(), String> {
        let job = self
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| format!("Job not found: {}", job_id))?;
        job.enabled = enabled;
        Ok(())
    }

    /// Check which jobs should fire at the given time and return their template IDs
    pub fn tick(&mut self, now: &DateTime<Utc>) -> Vec<String> {
        let mut triggered_templates = Vec::new();

        for (id, cron) in &self.parsed_crons {
            if let Some(job) = self.jobs.get(id) {
                if !job.enabled {
                    continue;
                }
                // Check max_runs
                if let Some(max) = job.max_runs {
                    if job.run_count >= max {
                        continue;
                    }
                }
                if cron.matches(now) {
                    // Avoid double-firing within the same minute
                    let already_ran = job.last_run.as_ref().is_some_and(|lr| {
                        if let Ok(last) = lr.parse::<DateTime<Utc>>() {
                            last.minute() == now.minute()
                                && last.hour() == now.hour()
                                && last.day() == now.day()
                        } else {
                            false
                        }
                    });

                    if !already_ran {
                        triggered_templates.push(job.template_id.clone());
                        // Update job state
                        if let Some(job_mut) = self.jobs.get_mut(id) {
                            job_mut.last_run = Some(now.to_rfc3339());
                            job_mut.run_count += 1;
                        }
                    }
                }
            }
        }

        triggered_templates
    }

    /// List all scheduled jobs
    pub fn list_jobs(&self) -> Vec<&ScheduledJob> {
        self.jobs.values().collect()
    }

    /// Get a specific job
    pub fn get_job(&self, job_id: &str) -> Option<&ScheduledJob> {
        self.jobs.get(job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_parse_every_minute() {
        let cron = CronExpression::parse("* * * * *").unwrap();
        let now = Utc::now();
        assert!(cron.matches(&now));
    }

    #[test]
    fn test_cron_parse_specific_time() {
        let cron = CronExpression::parse("30 9 * * 1").unwrap();
        // Should match 09:30 on any Monday
        let monday_930 = chrono::NaiveDate::from_ymd_opt(2026, 3, 30)
            .unwrap()
            .and_hms_opt(9, 30, 0)
            .unwrap()
            .and_utc();
        assert!(cron.matches(&monday_930));

        // Should NOT match 10:30
        let monday_1030 = chrono::NaiveDate::from_ymd_opt(2026, 3, 30)
            .unwrap()
            .and_hms_opt(10, 30, 0)
            .unwrap()
            .and_utc();
        assert!(!cron.matches(&monday_1030));
    }

    #[test]
    fn test_cron_step() {
        let cron = CronExpression::parse("*/5 * * * *").unwrap();
        let at_0 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap()
            .and_utc();
        let at_5 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(12, 5, 0)
            .unwrap()
            .and_utc();
        let at_3 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(12, 3, 0)
            .unwrap()
            .and_utc();

        assert!(cron.matches(&at_0));
        assert!(cron.matches(&at_5));
        assert!(!cron.matches(&at_3));
    }

    #[test]
    fn test_cron_range() {
        let cron = CronExpression::parse("* 9-17 * * *").unwrap();
        let at_10 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .and_utc();
        let at_20 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(20, 0, 0)
            .unwrap()
            .and_utc();

        assert!(cron.matches(&at_10));
        assert!(!cron.matches(&at_20));
    }

    #[test]
    fn test_scheduler_add_and_tick() {
        let mut sched = CronScheduler::new();
        let job = sched
            .add_job("Daily Report", "* * * * *", "tpl_weekly_sales")
            .unwrap();
        assert!(job.enabled);

        let now = Utc::now();
        let triggered = sched.tick(&now);
        assert_eq!(triggered.len(), 1);
        assert_eq!(triggered[0], "tpl_weekly_sales");

        // Second tick at same minute should NOT fire again
        let triggered2 = sched.tick(&now);
        assert!(triggered2.is_empty());
    }

    #[test]
    fn test_scheduler_disable_job() {
        let mut sched = CronScheduler::new();
        let job = sched.add_job("Test", "* * * * *", "tpl_test").unwrap();
        sched.set_enabled(&job.id, false).unwrap();

        let now = Utc::now();
        let triggered = sched.tick(&now);
        assert!(triggered.is_empty());
    }

    #[test]
    fn test_scheduler_max_runs() {
        let mut sched = CronScheduler::new();
        let job = sched
            .add_job("Limited", "* * * * *", "tpl_limited")
            .unwrap();
        sched.jobs.get_mut(&job.id).unwrap().max_runs = Some(1);

        let t1 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
            .and_utc();
        let triggered = sched.tick(&t1);
        assert_eq!(triggered.len(), 1);

        // Different minute but max_runs reached
        let t2 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(10, 1, 0)
            .unwrap()
            .and_utc();
        let triggered2 = sched.tick(&t2);
        assert!(triggered2.is_empty());
    }

    #[test]
    fn test_invalid_cron_expression() {
        let result = CronExpression::parse("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_cron_list_field() {
        let cron = CronExpression::parse("0,15,30,45 * * * *").unwrap();
        let at_15 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(12, 15, 0)
            .unwrap()
            .and_utc();
        let at_7 = chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
            .unwrap()
            .and_hms_opt(12, 7, 0)
            .unwrap()
            .and_utc();

        assert!(cron.matches(&at_15));
        assert!(!cron.matches(&at_7));
    }
}
