import { API, AppState, apiFetch, showToast, escapeHtml } from './core.js';

let extModules = [];
export let extCurrentFilter = 'all';
let extSearchTerm = '';
let extConfigTargetId = null;
let extReadinessTimer = null;

const EXT_CAT_ICONS = {
    notes:    'fa-note-sticky',
    compute:  'fa-microchip',
    security: 'fa-shield-halved',
    network:  'fa-network-wired',
    economy:  'fa-chart-line',
};

const MOCK_EXTENSIONS = [
    { id: 'memory-engine', name: 'Memory Engine', category: 'compute', status: 'Running', summary: 'Core cognitive processing', owner: 'System', version: '2.1', run_count: 5420 },
    { id: 'net-analyzer', name: 'Net Analyzer', category: 'network', status: 'Running', summary: 'Network traffic analysis', owner: 'Admin', version: '1.4', run_count: 120 },
    { id: 'sec-shield', name: 'Sec Shield', category: 'security', status: 'Warning', summary: 'Active threat detection', owner: 'System', version: '3.0', run_count: 890 },
    { id: 'eco-tracker', name: 'Eco Tracker', category: 'economy', status: 'Stopped', summary: 'Market tracking module', owner: 'TraderBot', version: '0.9', run_count: 0 },
    { id: 'notes-sync', name: 'Notes Sync', category: 'notes', status: 'Running', summary: 'Cross-device notes syncing', owner: 'User', version: '1.1', run_count: 34 }
];

export async function fetchExtensions() {
    try {
        const res = await apiFetch(`${API}/api/extensions`);
        if (res.ok) {
            const data = await res.json();
            extModules = (data.modules && data.modules.length > 0) ? data.modules : MOCK_EXTENSIONS;
        } else {
            extModules = MOCK_EXTENSIONS;
        }
    } catch(e) {
        if (window.appendSessionLog) window.appendSessionLog('Failed to load extensions, using fallback', 'error');
        extModules = MOCK_EXTENSIONS;
    }
    AppState.set('extensions', extModules);
    renderExtGrid();
    updateExtCatCounts();
}

export async function fetchExtReadiness() {
    try {
        const res = await apiFetch(`${API}/api/extensions/readiness`);
        if (!res.ok) return;
        const d = await res.json();
        const policyEl = document.getElementById('rdPolicyValue');
        const connEl   = document.getElementById('rdConnValue');
        const queueEl  = document.getElementById('rdQueueValue');
        const nextEl   = document.getElementById('rdNextReview');
        const policyBar = document.getElementById('rdPolicyBar');
        const connBar   = document.getElementById('rdConnBar');
        const queueBar  = document.getElementById('rdQueueBar');

        if (policyEl) policyEl.textContent = `${d.policy_checks.pending} pending, ${d.policy_checks.ok} ok`;
        if (connEl)   connEl.textContent   = `${d.data_connectors.healthy} healthy, ${d.data_connectors.degraded} degraded`;
        if (queueEl)  queueEl.textContent  = `${d.automation_queue.ready} ready, ${d.automation_queue.blocked} blocked`;

        const totalPolicy = d.policy_checks.pending + d.policy_checks.ok;
        if (policyBar) policyBar.style.width = `${Math.round((d.policy_checks.ok / (totalPolicy || 1)) * 100)}%`;
        const totalConn = d.data_connectors.healthy + d.data_connectors.degraded;
        if (connBar) connBar.style.width = `${Math.round((d.data_connectors.healthy / (totalConn || 1)) * 100)}%`;
        const totalQueue = d.automation_queue.ready + d.automation_queue.blocked;
        if (queueBar) queueBar.style.width = `${Math.round((d.automation_queue.ready / (totalQueue || 1)) * 100)}%`;

        if (nextEl && d.next_review_at) {
            const ms = new Date(d.next_review_at) - Date.now();
            const h = Math.floor(ms / 3600000);
            const m = Math.floor((ms % 3600000) / 60000);
            nextEl.textContent = ms > 0 ? `${h}h ${m}m` : 'Now';
        }
    } catch(_) {}
}

export function extStatusClass(status) {
    const s = String(status).toLowerCase();
    if (s === 'active')   return 'ext-status-active';
    if (s === 'ready')    return 'ext-status-ready';
    if (s === 'pending')  return 'ext-status-pending';
    if (s === 'error')    return 'ext-status-error';
    return 'ext-status-disabled';
}

export function renderExtGrid() {
    const grid = document.getElementById('extGrid');
    if (!grid) return;
    const term = extSearchTerm.toLowerCase();
    const list = extModules.filter(m => {
        const matchCat = extCurrentFilter === 'all' || m.category === extCurrentFilter;
        const matchTerm = !term ||
            (m.name || '').toLowerCase().includes(term) ||
            (m.summary || '').toLowerCase().includes(term) ||
            (m.owner || '').toLowerCase().includes(term);
        return matchCat && matchTerm;
    });

    if (list.length === 0) {
        grid.innerHTML = `<div style="grid-column:1/-1; padding:40px; text-align:center; color:var(--text-muted);">
            <i class="fa-solid fa-cube" style="font-size:28px; margin-bottom:10px; opacity:0.4;"></i>
            <p>No modules match "${escapeHtml(extSearchTerm || extCurrentFilter)}"</p>
        </div>`;
        return;
    }

    grid.innerHTML = list.map(m => {
        const icon = EXT_CAT_ICONS[m.category] || 'fa-puzzle-piece';
        const sc   = extStatusClass(m.status);
        const runs = m.run_count != null ? `${m.run_count} runs` : '';
        const ver  = m.version ? `v${m.version}` : '';
        return `
        <div class="ext-card" id="ext-card-${escapeHtml(m.id)}">
            <div class="ext-card-header">
                <div class="ext-icon ext-icon-${escapeHtml(m.category)}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div style="flex:1; min-width:0;">
                    <div class="ext-card-title">${escapeHtml(m.name)}</div>
                    <div style="display:flex; gap:6px; align-items:center; margin-top:3px;">
                        <span class="ext-status ${sc}">${escapeHtml(m.status)}</span>
                        <span style="font-size:10px; color:var(--text-muted);">${escapeHtml(ver)}</span>
                    </div>
                </div>
            </div>
            <div class="ext-card-summary">${escapeHtml(m.summary || '')}</div>
            <div class="ext-card-meta">
                <span><i class="fa-solid fa-user" style="opacity:0.5;"></i> ${escapeHtml(m.owner || '')}</span>
                <span style="margin-left:auto;"><i class="fa-solid fa-play" style="opacity:0.5;"></i> ${runs}</span>
            </div>
            <div class="ext-card-actions">
                <button class="btn" style="font-size:11px; padding:5px 10px;" onclick="openExtConfigModal('${escapeHtml(m.id)}')"><i class="fa-solid fa-sliders"></i> Configure</button>
                <button class="btn btn-primary" style="font-size:11px; padding:5px 10px;" onclick="runExtension('${escapeHtml(m.id)}', this)"><i class="fa-solid fa-play"></i> Run Now</button>
                <button class="btn" style="font-size:11px; padding:5px 10px;" onclick="openExtLogsModal('${escapeHtml(m.id)}', '${escapeHtml(m.name)}')"><i class="fa-solid fa-terminal"></i> Logs</button>
            </div>
        </div>`;
    }).join('');
}

export function updateExtCatCounts() {
    const cats = ['notes','compute','security','network','economy'];
    cats.forEach(cat => {
        const el = document.getElementById(`ecnt-${cat}`);
        if (el) el.textContent = extModules.filter(m => m.category === cat).length;
    });
    const allEl = document.getElementById('ecnt-all');
    if (allEl) allEl.textContent = extModules.length;
}

export function filterExtCat(cat, btn) {
    extCurrentFilter = cat;
    document.querySelectorAll('.ext-cat-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    renderExtGrid();
}

export function searchExtensions(value) {
    extSearchTerm = String(value || '');
    renderExtGrid();
}

export async function runExtension(extId, btn) {
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>'; }
    try {
        const res = await apiFetch(`${API}/api/extensions/${extId}/run`, { method: 'POST' });
        if (res.ok) {
            showToast(`Module ${extId} run triggered`, 'success');
        } else {
            showToast('Run failed', 'error');
        }
    } catch(e) {
        showToast('Network error', 'error');
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Now'; }
    }
}

export function openExtConfigModal(extId) {
    extConfigTargetId = extId;
    const m = extModules.find(x => x.id === extId);
    const cronEl    = document.getElementById('extConfigCron');
    const paramsEl  = document.getElementById('extConfigParams');
    if (cronEl)   cronEl.value   = (m?.config?.schedule_cron) || '';
    if (paramsEl) paramsEl.value = m?.config ? JSON.stringify(m.config, null, 2) : '';
    document.getElementById('extConfigModal').classList.add('open');
}

export async function saveExtConfig() {
    if (!extConfigTargetId) return;
    let params = {};
    try { params = JSON.parse(document.getElementById('extConfigParams')?.value || '{}'); } catch(_) {}
    const cron = document.getElementById('extConfigCron')?.value;
    if (cron) params.schedule_cron = cron;
    try {
        const res = await apiFetch(`${API}/api/extensions/${extConfigTargetId}/config`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ params })
        });
        if (res.ok) {
            showToast('Configuration saved', 'success');
            closeExtModal('extConfigModal');
            fetchExtensions();
        } else {
            showToast('Save failed', 'error');
        }
    } catch(e) { showToast('Network error', 'error'); }
}

export async function openExtLogsModal(extId, extName) {
    const modal = document.getElementById('extLogsModal');
    const table = document.getElementById('extLogsTable');
    if (!modal || !table) return;
    // Update title
    modal.querySelector('.ext-modal-title').innerHTML = `<i class="fa-solid fa-terminal"></i> ${escapeHtml(extName)}  - Execution History`;
    table.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</div>';
    modal.classList.add('open');
    try {
        const res = await apiFetch(`${API}/api/extensions/${extId}/runs`);
        if (res.ok) {
            const data = await res.json();
            const runs = data.runs || [];
            if (!runs.length) {
                table.innerHTML = '<div style="color:var(--text-muted); padding:20px; text-align:center;">No runs yet.</div>';
                return;
            }
            table.innerHTML = runs.map(r => {
                const statusColor = r.status === 'Succeeded' ? '#6ee7b7' : r.status === 'Failed' ? '#fca5a5' : '#fcd34d';
                const dur = r.duration_ms != null ? `${(r.duration_ms/1000).toFixed(1)}s` : '-';
                const started = r.started_at ? new Date(r.started_at).toLocaleString() : '-';
                return `<div style="display:flex; align-items:center; gap:10px; padding:8px 10px; background:var(--surface-800); border-radius:8px; font-size:11px;">
                    <span style="color:${statusColor}; font-weight:600;">${escapeHtml(r.status)}</span>
                    <span style="color:var(--text-muted); flex:1;">${started}</span>
                    <span style="color:var(--text-muted);">${dur}</span>
                </div>`;
            }).join('');
        }
    } catch(e) {
        table.innerHTML = '<div style="color:var(--accent-red); padding:20px;">Failed to load history</div>';
    }
}

export function openAddModuleModal() {
    document.getElementById('extAddModal').classList.add('open');
}

export async function saveNewModule() {
    const id      = document.getElementById('addModuleId')?.value.trim();
    const name    = document.getElementById('addModuleName')?.value.trim();
    const cat     = document.getElementById('addModuleCat')?.value;
    const owner   = document.getElementById('addModuleOwner')?.value.trim();
    const version = document.getElementById('addModuleVersion')?.value.trim();
    const desc    = document.getElementById('addModuleDesc')?.value.trim();
    if (!name) { showToast('Module name is required', 'error'); return; }
    try {
        const res = await apiFetch(`${API}/api/extensions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, name, category: cat, owner, version, description: desc })
        });
        if (res.ok) {
            showToast(`Module "${name}" registered`, 'success');
            closeExtModal('extAddModal');
            fetchExtensions();
        } else {
            showToast('Registration failed', 'error');
        }
    } catch(e) { showToast('Network error', 'error'); }
}

export function closeExtModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
}

export function refreshExtensions() {
    fetchExtensions();
    fetchExtReadiness();
    showToast('Extension status synced', 'success');
}

export function startExtReadinessTimer() {
    if (extReadinessTimer) clearInterval(extReadinessTimer);
    extReadinessTimer = setInterval(fetchExtReadiness, 30000);
}

export function setExtModules(modules) {
    extModules = modules;
}

export function setExtCurrentFilter(filter) {
    extCurrentFilter = filter;
}

export function getExtCurrentFilter() {
    return extCurrentFilter;
}
