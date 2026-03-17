/// Embedded HTML chat page (compiled into the binary)
pub const CHAT_HTML: &str = include_str!("../../static/chat.html");

/// Embedded HTML dashboard page (compiled into the binary)
pub const DASHBOARD_HTML: &str = include_str!("../../static/dashboard.html");

/// Embedded dashboard CSS
pub const DASHBOARD_CSS: &str = include_str!("../../static/dashboard.css");

/// Embedded dashboard JS modules
pub const DASHBOARD_CORE_JS: &str = include_str!("../../static/js/dashboard/core.js");
pub const DASHBOARD_CHAT_JS: &str = include_str!("../../static/js/dashboard/chat.js");
pub const DASHBOARD_INDEX_JS: &str = include_str!("../../static/js/dashboard/index.js");

/// Embedded HTML activity feed page (compiled into the binary)
pub const ACTIVITY_FEED_HTML: &str = include_str!("../../static/activity_feed.html");

/// Embedded HTML sessions list page (compiled into the binary)
pub const SESSIONS_HTML: &str = include_str!("../../static/sessions.html");

/// Embedded HTML session detail page (compiled into the binary)
pub const SESSION_DETAIL_HTML: &str = include_str!("../../static/session_detail.html");

/// Embedded HTML search page (compiled into the binary)
pub const SEARCH_HTML: &str = include_str!("../../static/search.html");

/// Embedded HTML statistics page (compiled into the binary)
pub const STATS_HTML: &str = include_str!("../../static/stats.html");

/// Embedded HTML team network map page (compiled into the binary)
pub const TEAM_MAP_HTML: &str = include_str!("../../static/team_map.html");

/// Pretty HTML for rate limiting
pub const TOO_MANY_REQUESTS_HTML: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Slow Down — EdgeClaw</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; background: #050508; color: #f8fafc; height: 100vh; display: flex; align-items: center; justify-content: center; margin: 0; }
        .card { background: #12121a; border: 1px solid #2a2a3a; padding: 40px; border-radius: 16px; text-align: center; max-width: 400px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }
        h1 { color: #6366f1; margin: 0 0 16px; font-size: 24px; }
        p { color: #94a3b8; line-height: 1.6; margin-bottom: 24px; }
        .btn { background: #6366f1; color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; text-decoration: none; font-weight: 600; transition: 0.3s; }
        .btn:hover { background: #818cf8; transform: translateY(-2px); }
        .icon { font-size: 48px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">⌛</div>
        <h1>Too Many Requests</h1>
        <p>Whoa there! You're refreshing a bit too fast. Please take a second to breathe while we cool down the engines.</p>
        <a href="javascript:location.reload()" class="btn">Try Again</a>
    </div>
    <script>setTimeout(() => location.reload(), 5000);</script>
</body>
</html>
"#;
