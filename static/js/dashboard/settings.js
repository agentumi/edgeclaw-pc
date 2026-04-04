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
            const indexVal = document.getElementById('settingsAgentIndex')?.value || 'main';
            let agent = config.agent || {};

            if (indexVal !== 'main') {
                const idx = parseInt(indexVal);
                if (config.webui && config.webui.fleet_identities && config.webui.fleet_identities[idx]) {
                    agent = config.webui.fleet_identities[idx];
                } else {
                    // Default fallbacks if not explicitly set in config
                    agent = {
                        display_name: `Agent-${idx + 1}`,
                        persona: '',
                        role: '',
                        device_name: config.agent.device_name + '-' + (idx + 1)
                    };
                }
            }
            
            // Map values to actual input fields from settings.html
            const el = (id) => document.getElementById(id);
            if (el('settingsDisplayName')) el('settingsDisplayName').value = agent.display_name || '';
            if (el('settingsDeviceName')) el('settingsDeviceName').value = agent.device_name || '';
            if (el('settingsAvatarUrl')) el('settingsAvatarUrl').value = agent.avatar_url || '';
            if (el('settingsPersona')) el('settingsPersona').value = agent.persona || '';
            if (el('settingsRole')) el('settingsRole').value = agent.role || '';
            if (el('settingsEmail')) el('settingsEmail').value = agent.email || '';
            if (el('settingsMessenger')) el('settingsMessenger').value = agent.messenger || '';
            if (el('settingsPhone')) el('settingsPhone').value = agent.phone || '';

            if (el('settingsAvatarPreview')) {
                if (agent.avatar_url) {
                    el('settingsAvatarPreview').src = agent.avatar_url;
                    el('settingsAvatarPreview').style.display = 'block';
                } else {
                    el('settingsAvatarPreview').style.display = 'none';
                }
            }
            
            // Bind Save Button Event (Inject Persona)
            const saveBtn = el('settingsIdentitySaveBtn');
            if (saveBtn) {
                // Ensure no duplicate bindings by replacing the node
                const newBtn = saveBtn.cloneNode(true);
                saveBtn.parentNode.replaceChild(newBtn, saveBtn);
                newBtn.addEventListener('click', saveIdentityConfig);
            }
        }
    } catch (e) { console.error("[V2.4] Persona Load Error", e); }
}

async function saveIdentityConfig() {
    const el = (id) => document.getElementById(id)?.value || '';
    const indexVal = document.getElementById('settingsAgentIndex')?.value || 'main';
    const payload = {
        display_name: el('settingsDisplayName'),
        device_name: el('settingsDeviceName'),
        avatar_url: el('settingsAvatarUrl'),
        persona: el('settingsPersona'),
        role: el('settingsRole'),
        email: el('settingsEmail'),
        messenger: el('settingsMessenger'),
        phone: el('settingsPhone'),
        language: document.getElementById('aiChatLangSelect')?.value || 'english',
        instance_index: indexVal === 'main' ? null : parseInt(indexVal)
    };

    const btn = document.getElementById('settingsIdentitySaveBtn');
    if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

    try {
        const res = await apiFetch(`${API}/api/config/identity`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (res.ok) {
            showToast('Persona successfully injected & persistent!', 'success');
        } else {
            showToast('Failed to save persona.', 'error');
        }
    } catch (e) {
        showToast('Network error while saving persona.', 'error');
    } finally {
        if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i> Save';
    }
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
