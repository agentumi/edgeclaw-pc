import { API, apiFetch, showToast, setTranslatedText, escapeHtml } from './core.js';

export async function switchSettingsTab(tabId) {
    // Update tab buttons
    document.querySelectorAll('.settings-tab').forEach(btn => {
        btn.classList.toggle('active', btn.id === `stab-${tabId}`);
    });
    // Update panels
    document.querySelectorAll('.settings-panel').forEach(panel => {
        panel.classList.toggle('active', panel.id === `spanel-${tabId}`);
    });
    // Load data for specific tabs
    if (tabId === 'security') loadSecurityTab();
    if (tabId === 'profile') loadSettingsIdentity();
}

export async function loadSecurityTab() {
    const keyEl = document.getElementById('settingsApiKey');
    if (!keyEl) return;
    try {
        const [statusRes, configRes] = await Promise.all([
            apiFetch(`${API}/api/status`),
            apiFetch(`${API}/api/config`),
        ]);
        const status = statusRes.ok ? await statusRes.json() : {};
        const config = configRes.ok ? await configRes.json() : {};
        const agent = config.agent || {};
        const device = agent.display_name || agent.device_name || status.hostname || 'EdgeClaw';
        const host = status.hostname || agent.device_name || 'localhost';
        const port = status.port || agent.listen_port || '';
        keyEl.textContent = port ? `${device}@${host}:${port}` : device;
    } catch (_) {
        keyEl.textContent = 'Unable to load API key';
    }
}

export async function loadSettingsIdentity() {
    try {
        const res = await apiFetch(`${API}/api/config`);
        if (res.ok) {
            const config = await res.json();
            const agent = config.agent || {};
            const nameEl = document.getElementById('settings-identity-name');
            const roleEl = document.getElementById('settings-identity-role');
            const avatarEl = document.getElementById('settings-identity-avatar');
            
            if (nameEl) nameEl.textContent = agent.display_name || agent.device_name || 'EdgeClaw User';
            if (roleEl) roleEl.textContent = agent.role || 'Administrator';
            if (avatarEl && agent.avatar_url) avatarEl.src = agent.avatar_url;
        }
    } catch (e) {}
}

export function copyApiKey() {
    const keyEl = document.getElementById('settingsApiKey');
    if (!keyEl) return;
    navigator.clipboard.writeText(keyEl.textContent).then(() => {
        showToast('API Key copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy. Please select and copy manually', 'error');
    });
}

export function regenerateApiKey() {
    if (!confirm('Regenerating the API key will disconnect all active sessions. Continue?')) return;
    showToast('API key rotation is managed by node restart', 'info');
}
