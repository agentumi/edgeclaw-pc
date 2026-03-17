/// Viewer can read activities/sessions/stats.
/// Operator can additionally search.
/// Admin and Owner can access everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ApiAccessLevel {
    /// Any authenticated user
    Viewer = 0,
    /// Viewer + search/export
    Operator = 1,
    /// Operator + config/write ops
    Admin = 2,
    /// All access
    Owner = 3,
}

/// Determine the required access level for an API path.
pub fn required_access_level(method: &str, path: &str) -> ApiAccessLevel {
    match (method, path) {
        // Read-only endpoints: Viewer
        ("GET", p)
            if p.starts_with("/api/activities")
                || p.starts_with("/api/sessions")
                || p == "/api/status"
                || p == "/api/market/stats"
                || (p.starts_with("/api/agents/") && p.ends_with("/metrics"))
                || p == "/api/health" =>
        {
            ApiAccessLevel::Viewer
        }
        // Search/stats: Operator
        ("POST", "/api/activities/search") => ApiAccessLevel::Operator,
        // Config changes: Admin
        ("PUT", "/api/config") => ApiAccessLevel::Admin,
        ("PUT", "/api/config/identity") => ApiAccessLevel::Admin,
        ("PUT", "/api/config/avatar") => ApiAccessLevel::Admin,
        ("GET", "/api/rent-policies") => ApiAccessLevel::Viewer,
        ("PUT", "/api/rent-policies") => ApiAccessLevel::Admin,
        // Agent execution: Admin
        _ if method == "POST" && path.contains("/execute") => ApiAccessLevel::Admin,
        // Everything else: Viewer
        _ => ApiAccessLevel::Viewer,
    }
}
