//! Marketing automation workflows.
//!
//! Provides [`SeoChecker`], [`ContentCalendar`], and [`ReportGenerator`]
//! for handling SEO analysis, content scheduling, and weekly report
//! generation.

use crate::error::AgentError;
use chrono::{DateTime, Utc};
use std::path::PathBuf;

// ─── SEO Checker ───────────────────────────────────────────

/// Lightweight HTML SEO checker.
pub struct SeoChecker;

/// SEO analysis result for a URL.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeoReport {
    pub url: String,
    pub title: Option<String>,
    pub meta_description: Option<String>,
    pub h1_count: usize,
    pub img_without_alt: usize,
    pub response_time_ms: u64,
    pub score: u32,
    pub issues: Vec<String>,
}

impl SeoChecker {
    /// Fetch a URL and produce a basic SEO report.
    pub fn check_url(url: &str) -> SeoReport {
        let start = std::time::Instant::now();

        let body = match ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .get(url)
            .call()
        {
            Ok(resp) => resp.into_string().unwrap_or_default(),
            Err(_) => {
                return SeoReport {
                    url: url.to_string(),
                    title: None,
                    meta_description: None,
                    h1_count: 0,
                    img_without_alt: 0,
                    response_time_ms: start.elapsed().as_millis() as u64,
                    score: 0,
                    issues: vec!["Failed to fetch URL".into()],
                };
            }
        };

        let elapsed = start.elapsed().as_millis() as u64;
        let mut issues = Vec::new();
        let mut score: u32 = 100;

        // Title
        let title = Self::extract_tag(&body, "title");
        if title.is_none() {
            issues.push("Missing <title> tag".into());
            score = score.saturating_sub(20);
        }

        // Meta description
        let meta_description = Self::extract_meta(&body, "description");
        if meta_description.is_none() {
            issues.push("Missing meta description".into());
            score = score.saturating_sub(15);
        }

        // H1 count
        let h1_count = body.matches("<h1").count();
        if h1_count == 0 {
            issues.push("No <h1> tag found".into());
            score = score.saturating_sub(15);
        } else if h1_count > 1 {
            issues.push(format!("Multiple <h1> tags ({h1_count})"));
            score = score.saturating_sub(5);
        }

        // Images without alt
        let img_without_alt = Self::count_images_without_alt(&body);
        if img_without_alt > 0 {
            issues.push(format!("{img_without_alt} images missing alt attribute"));
            score = score.saturating_sub(std::cmp::min(img_without_alt as u32 * 5, 20));
        }

        // Response time
        if elapsed > 3000 {
            issues.push(format!("Slow response: {elapsed}ms"));
            score = score.saturating_sub(10);
        }

        SeoReport {
            url: url.to_string(),
            title,
            meta_description,
            h1_count,
            img_without_alt,
            response_time_ms: elapsed,
            score,
            issues,
        }
    }

    /// Extract text content of an HTML tag (simple).
    fn extract_tag(html: &str, tag: &str) -> Option<String> {
        let open = format!("<{tag}");
        let close = format!("</{tag}>");
        if let Some(start) = html.find(&open) {
            if let Some(gt) = html[start..].find('>') {
                let after = start + gt + 1;
                if let Some(end) = html[after..].find(&close) {
                    let text = html[after..after + end].trim().to_string();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }
        }
        None
    }

    /// Extract meta tag content by name.
    fn extract_meta(html: &str, name: &str) -> Option<String> {
        let pattern = format!("name=\"{name}\"");
        if let Some(pos) = html.find(&pattern) {
            // Look for content="..." nearby
            let region = &html[pos..std::cmp::min(pos + 500, html.len())];
            if let Some(c) = region.find("content=\"") {
                let start = c + 9;
                if let Some(end) = region[start..].find('"') {
                    let text = region[start..start + end].trim().to_string();
                    if !text.is_empty() {
                        return Some(text);
                    }
                }
            }
        }
        None
    }

    /// Count <img> tags that lack an `alt` attribute.
    fn count_images_without_alt(html: &str) -> usize {
        let mut count = 0;
        let mut search_from = 0;
        while let Some(pos) = html[search_from..].find("<img") {
            let abs = search_from + pos;
            let end = html[abs..].find('>').unwrap_or(0);
            let tag = &html[abs..abs + end + 1];
            if !tag.contains("alt=") {
                count += 1;
            }
            search_from = abs + end + 1;
        }
        count
    }
}

// ─── Content Calendar ──────────────────────────────────────

/// JSON-backed content calendar.
pub struct ContentCalendar {
    entries: Vec<CalendarEntry>,
    path: PathBuf,
}

/// Single calendar entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CalendarEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub scheduled_at: DateTime<Utc>,
    pub platform: String,
    pub done: bool,
}

impl ContentCalendar {
    /// Create a new in-memory calendar (call `load` to hydrate from disk).
    pub fn new(path: PathBuf) -> Self {
        Self {
            entries: Vec::new(),
            path,
        }
    }

    /// Load entries from JSON file.
    pub fn load(&mut self) -> Result<(), AgentError> {
        if !self.path.exists() {
            return Ok(());
        }
        let data = std::fs::read_to_string(&self.path)?;
        self.entries = serde_json::from_str(&data)?;
        Ok(())
    }

    /// Save entries to JSON file.
    pub fn save(&self) -> Result<(), AgentError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    /// Add a new entry.
    pub fn add_entry(&mut self, entry: CalendarEntry) {
        self.entries.push(entry);
    }

    /// List entries scheduled in the future.
    pub fn list_upcoming(&self) -> Vec<&CalendarEntry> {
        let now = Utc::now();
        self.entries
            .iter()
            .filter(|e| !e.done && e.scheduled_at > now)
            .collect()
    }

    /// Mark an entry as done.
    pub fn mark_done(&mut self, id: &str) -> bool {
        if let Some(e) = self.entries.iter_mut().find(|e| e.id == id) {
            e.done = true;
            true
        } else {
            false
        }
    }

    /// List all entries.
    pub fn list_all(&self) -> &[CalendarEntry] {
        &self.entries
    }
}

// ─── Report Generator ──────────────────────────────────────

/// Markdown/HTML report generator.
pub struct ReportGenerator;

/// Weekly report data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WeeklyReport {
    pub title: String,
    pub period: String,
    pub markdown: String,
    pub total_entries: usize,
    pub completed: usize,
}

impl ReportGenerator {
    /// Generate a weekly markdown report from calendar entries.
    pub fn weekly_report(calendar: &ContentCalendar) -> WeeklyReport {
        let now = Utc::now();
        let week_ago = now - chrono::Duration::days(7);

        let recent: Vec<&CalendarEntry> = calendar
            .list_all()
            .iter()
            .filter(|e| e.scheduled_at > week_ago && e.scheduled_at <= now)
            .collect();

        let completed = recent.iter().filter(|e| e.done).count();
        let total = recent.len();

        let mut md = String::from("# Weekly Content Report\n\n");
        md.push_str(&format!(
            "**Period:** {} — {}\n\n",
            week_ago.format("%Y-%m-%d"),
            now.format("%Y-%m-%d")
        ));
        md.push_str(&format!("**Completed:** {completed}/{total} entries\n\n"));
        md.push_str("## Entries\n\n");
        for entry in &recent {
            let status = if entry.done { "✅" } else { "❌" };
            md.push_str(&format!(
                "- {} **{}** ({}) — {}\n",
                status, entry.title, entry.platform, entry.description
            ));
        }

        WeeklyReport {
            title: "Weekly Content Report".into(),
            period: format!(
                "{} — {}",
                week_ago.format("%Y-%m-%d"),
                now.format("%Y-%m-%d")
            ),
            markdown: md,
            total_entries: total,
            completed,
        }
    }

    /// Convert markdown to a basic HTML page.
    pub fn export_html(report: &WeeklyReport) -> String {
        // Simple markdown → HTML conversion for headings, bold, and lists
        let mut html = String::from(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Report</title></head><body>\n",
        );
        for line in report.markdown.lines() {
            if let Some(heading) = line.strip_prefix("# ") {
                html.push_str(&format!("<h1>{heading}</h1>\n"));
            } else if let Some(heading) = line.strip_prefix("## ") {
                html.push_str(&format!("<h2>{heading}</h2>\n"));
            } else if let Some(item) = line.strip_prefix("- ") {
                html.push_str(&format!("<li>{item}</li>\n"));
            } else if line.is_empty() {
                html.push_str("<br>\n");
            } else {
                html.push_str(&format!("<p>{line}</p>\n"));
            }
        }
        html.push_str("</body></html>");
        html
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seo_extract_title() {
        let html = "<html><head><title>My Page</title></head></html>";
        let title = SeoChecker::extract_tag(html, "title");
        assert_eq!(title, Some("My Page".to_string()));
    }

    #[test]
    fn test_seo_extract_meta() {
        let html = r#"<meta name="description" content="Hello world">"#;
        let desc = SeoChecker::extract_meta(html, "description");
        assert_eq!(desc, Some("Hello world".to_string()));
    }

    #[test]
    fn test_seo_images_without_alt() {
        let html = r#"<img src="a.png"><img src="b.png" alt="B"><img src="c.png">"#;
        let count = SeoChecker::count_images_without_alt(html);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_calendar_crud() {
        let path = std::env::temp_dir().join("edgeclaw_test_calendar.json");
        let _ = std::fs::remove_file(&path);

        let mut cal = ContentCalendar::new(path.clone());
        cal.add_entry(CalendarEntry {
            id: "1".into(),
            title: "Blog Post".into(),
            description: "Write intro".into(),
            scheduled_at: Utc::now() + chrono::Duration::days(1),
            platform: "blog".into(),
            done: false,
        });
        assert_eq!(cal.list_all().len(), 1);
        assert_eq!(cal.list_upcoming().len(), 1);

        cal.mark_done("1");
        assert_eq!(cal.list_upcoming().len(), 0);

        cal.save().unwrap();
        let mut cal2 = ContentCalendar::new(path.clone());
        cal2.load().unwrap();
        assert_eq!(cal2.list_all().len(), 1);
        assert!(cal2.list_all()[0].done);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_weekly_report() {
        let path = std::env::temp_dir().join("edgeclaw_test_report_cal.json");
        let mut cal = ContentCalendar::new(path);
        cal.add_entry(CalendarEntry {
            id: "r1".into(),
            title: "Post A".into(),
            description: "desc".into(),
            scheduled_at: Utc::now() - chrono::Duration::days(1),
            platform: "twitter".into(),
            done: true,
        });
        cal.add_entry(CalendarEntry {
            id: "r2".into(),
            title: "Post B".into(),
            description: "desc".into(),
            scheduled_at: Utc::now() - chrono::Duration::hours(2),
            platform: "blog".into(),
            done: false,
        });

        let report = ReportGenerator::weekly_report(&cal);
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.completed, 1);
        assert!(report.markdown.contains("Post A"));
    }

    #[test]
    fn test_export_html() {
        let report = WeeklyReport {
            title: "Test".into(),
            period: "2024-01-01 — 2024-01-07".into(),
            markdown: "# Report\n\n- Item 1\n- Item 2\n".into(),
            total_entries: 2,
            completed: 1,
        };
        let html = ReportGenerator::export_html(&report);
        assert!(html.contains("<h1>Report</h1>"));
        assert!(html.contains("<li>Item 1</li>"));
    }

    #[test]
    fn test_seo_report_serialize() {
        let report = SeoReport {
            url: "https://example.com".into(),
            title: Some("Example".into()),
            meta_description: None,
            h1_count: 1,
            img_without_alt: 0,
            response_time_ms: 200,
            score: 85,
            issues: vec!["Missing meta description".into()],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("example.com"));
    }
}
