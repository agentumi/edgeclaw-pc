---
name: business-automation-reporting
description: Skills for managing YAML templates and generating business intelligence reports.
---

# Business Automation Skill

This skill is activated when working with files in `templates/business/` or calculating metrics for reports.

## Template Standards
- **Schema**: Must match the workflow engine's YAML parser schema.
- **Variables**: Use `{{variable}}` syntax for dynamic values.
- **Validation**: Ensure all mandatory fields (id, name, version) are present.

## Reporting Logic
- **Data Collection**: Use `activity_log` and `memory_engine` capabilities to gather background data.
- **KPIs**: 
    - Sales: Revenue, Conversion Rate, Lead Time.
    - Performance: Task Completion Rate, Uptime.
- **Formatting**: Output should be clean Markdown or structured CSV/JSON as requested.

## Workflow Patterns
1. **Fetch**: Query activity logs for the specified time range.
2. **Transform**: Aggregate data into KPIs.
3. **Render**: Populate the YAML template or Markdown report.
4. **Audit**: Log the report generation event.
