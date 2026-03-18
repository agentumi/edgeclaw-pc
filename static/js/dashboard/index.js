import { API, AppState, apiFetch, showToast, setTranslatedText } from './core.js';
import { initChat, initAIChat } from './chat.js';

    

    // Tab Navigation Logic
    const navItems = document.querySelectorAll('.nav-item');
    const views = document.querySelectorAll('.view-content');
    let currentMode = 'sanctum';
    const balanceDisplay = document.getElementById('balance-display');
    const modeIndicator = document.getElementById('mode-indicator');
    const modeIcon = document.getElementById('mode-icon');
    const modeText = document.getElementById('mode-text');
    let selectedAgentId = 'local';
    let selectedAgentName = 'local';
    let cachedAgents = [];
    let lastStatus = null;
    let lastTasks = [];
    let lastMemory = null;
    let lastAgentsSummary = null;
    let lastActivityStats = null;
    let lastActivityEntries = [];
    let lastMarketStats = null;
    let currentMarketCategory = 'processes';
    const navSubItems = document.querySelectorAll('.nav-subitem');
    const viewBreadcrumb = document.getElementById('view-breadcrumb');
    //     Phase 6+7: Extensions State                                         
    let extModules = [];
    let extCurrentFilter = 'all';
    let extSearchTerm = '';
    let extConfigTargetId = null;
    let extReadinessTimer = null;

    // Category icon map
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

    async function fetchExtensions() {
        try {
            const res = await apiFetch(`${API}/api/extensions`);
            if (res.ok) {
                const data = await res.json();
                extModules = (data.modules && data.modules.length > 0) ? data.modules : MOCK_EXTENSIONS;
            } else {
                extModules = MOCK_EXTENSIONS;
            }
        } catch(e) {
            appendSessionLog('Failed to load extensions, using fallback', 'error');
            extModules = MOCK_EXTENSIONS;
        }
        AppState.set('extensions', extModules);
        renderExtGrid();
        updateExtCatCounts();
    }

    async function fetchExtReadiness() {
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

    function extStatusClass(status) {
        const s = String(status).toLowerCase();
        if (s === 'active')   return 'ext-status-active';
        if (s === 'ready')    return 'ext-status-ready';
        if (s === 'pending')  return 'ext-status-pending';
        if (s === 'error')    return 'ext-status-error';
        return 'ext-status-disabled';
    }

    function renderExtGrid() {
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

    function updateExtCatCounts() {
        const cats = ['notes','compute','security','network','economy'];
        cats.forEach(cat => {
            const el = document.getElementById(`ecnt-${cat}`);
            if (el) el.textContent = extModules.filter(m => m.category === cat).length;
        });
        const allEl = document.getElementById('ecnt-all');
        if (allEl) allEl.textContent = extModules.length;
    }

    function filterExtCat(cat, btn) {
        extCurrentFilter = cat;
        document.querySelectorAll('.ext-cat-btn').forEach(b => b.classList.remove('active'));
        if (btn) btn.classList.add('active');
        renderExtGrid();
    }

    function searchExtensions(value) {
        extSearchTerm = String(value || '');
        renderExtGrid();
    }

    async function runExtension(extId, btn) {
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

    function openExtConfigModal(extId) {
        extConfigTargetId = extId;
        const m = extModules.find(x => x.id === extId);
        const cronEl    = document.getElementById('extConfigCron');
        const paramsEl  = document.getElementById('extConfigParams');
        if (cronEl)   cronEl.value   = (m?.config?.schedule_cron) || '';
        if (paramsEl) paramsEl.value = m?.config ? JSON.stringify(m.config, null, 2) : '';
        document.getElementById('extConfigModal').classList.add('open');
    }

    async function saveExtConfig() {
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

    async function openExtLogsModal(extId, extName) {
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

    function openAddModuleModal() {
        document.getElementById('extAddModal').classList.add('open');
    }

    async function saveNewModule() {
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

    function closeExtModal(id) {
        const el = document.getElementById(id);
        if (el) el.classList.remove('open');
    }

    function refreshExtensions() {
        fetchExtensions();
        fetchExtReadiness();
        showToast('Extension status synced', 'success');
    }

    // Legacy compat (old nav subitem handler)
    function addExtension() { openAddModuleModal(); }
    let activeExtensionFilter = 'all'; // kept for hash routing compat
    let extensionSearchTerm = '';      // kept for old search ref

    function normalizeAgentStatus(status) {
        return String(status || 'offline').toLowerCase();
    }

    function taskColumnId(status) {
        const normalized = String(status || '').toLowerCase();
        if (normalized === 'backlog' || normalized === 'todo') return 'todo';
        if (normalized === 'inprogress' || normalized === 'in_progress' || normalized === 'progress' || normalized === 'review') return 'progress';
        if (normalized === 'done') return 'done';
        return 'todo';
    }

    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function containsHangul(value) {
        return /[\u3131-\uD79D]/.test(String(value || ''));
    }

    function extractJsonArray(value) {
        if (!value) return null;
        try {
            return JSON.parse(value);
        } catch (_) {
            const match = String(value).match(/\[[\s\S]*\]/);
            if (!match) return null;
            try {
                return JSON.parse(match[0]);
            } catch (_) {
                return null;
            }
        }
    }

    function viewNameFromId(viewId) {
        const map = {
            'view-dashboard': 'Mission Control',
            'view-board': 'Agent Board',
            'view-memory': 'Memory',
            'view-market': 'Marketplace',
            'view-automations': 'Automations',
            'view-extensions': 'Extensions',
            'view-settings': 'Settings',
            'view-chat': 'Command Center',
            'view-aichat': 'Intoran AI'
        };
        return map[viewId] || 'EdgeClaw';
    }

    function updateBreadcrumb(viewId) {
        if (!viewBreadcrumb) return;
        viewBreadcrumb.textContent = viewNameFromId(viewId);
    }

    function applyViewSideEffects(viewId) {
        if (viewId === 'view-market') {
            setMode('market');
            fetchMarketplaceAgents();
            fetchMarketStats();
        } else if (viewId === 'view-dashboard') {
            setMode('sanctum');
            fetchStatus();
        } else if (viewId === 'view-board') {
            fetchTasks();
            fetchAgentGraph();
        } else if (viewId === 'view-memory') {
            fetchMemory();
        } else if (viewId === 'view-automations') {
            setMode('automation');
            fetchTemplates();
        } else if (viewId === 'view-settings') {
            setMode('sanctum');
            loadSettingsIdentity();
        } else if (viewId === 'view-extensions') {
            setMode('sanctum');
            fetchExtensions();
            fetchExtReadiness();
            // Start 30s polling for readiness panel
            if (extReadinessTimer) clearInterval(extReadinessTimer);
            extReadinessTimer = setInterval(fetchExtReadiness, 30000);
        } else {
            setMode('sanctum');
        }
    }

    function setActiveView(viewId, options = {}) {
        const { updateHash = true, extensionFilter = null } = options;
        const targetView = document.getElementById(viewId);
        if (!targetView) {
            console.error(`Missing target view: ${viewId}`);
            showToast(`View not found: ${viewId}`, 'error');
            return;
        }

        if (viewId === 'view-extensions' && !extensionFilter) {
            activeExtensionFilter = 'all';
            extCurrentFilter = 'all';
        } else if (extensionFilter) {
            activeExtensionFilter = extensionFilter;
            extCurrentFilter = extensionFilter;
        }

        navItems.forEach(n => n.classList.remove('active'));
        navSubItems.forEach(n => n.classList.remove('active'));

        const mainNav = Array.from(navItems).find(n => n.dataset.target === viewId);
        if (mainNav) mainNav.classList.add('active');

        if (viewId === 'view-extensions' && extensionFilter) {
            const sub = Array.from(navSubItems).find(n => n.dataset.extension === extensionFilter);
            if (sub) sub.classList.add('active');
            // Also activate the in-view category button
            const catBtn = document.querySelector(`.ext-cat-btn[data-cat="${extensionFilter}"]`);
            if (catBtn) filterExtCat(extensionFilter, catBtn);
        }

        views.forEach(v => v.classList.remove('active'));
        targetView.classList.add('active');

        if (updateHash) {
            const hashValue = viewId.replace('view-', '');
            const suffix = viewId === 'view-extensions' && activeExtensionFilter !== 'all'
                ? `:${activeExtensionFilter}`
                : '';
            window.location.hash = `${hashValue}${suffix}`;
        }

        updateBreadcrumb(viewId);
        applyViewSideEffects(viewId);
        showToast(`${viewNameFromId(viewId)} View Activated`, 'info');
    }

    function activateViewFromHash() {
        const rawHash = window.location.hash.replace('#', '').trim();
        if (!rawHash) {
            setActiveView('view-dashboard', { updateHash: false });
            return;
        }
        const [viewKey, extensionKey] = rawHash.split(':');
        const viewId = `view-${viewKey}`;
        if (document.getElementById(viewId)) {
            setActiveView(viewId, { updateHash: false, extensionFilter: extensionKey || null });
        } else {
            setActiveView('view-dashboard', { updateHash: false });
        }
    }

    // Extensions rendering: handled by fetchExtensions() + renderExtGrid() defined above

    function normalizeCapabilities(value) {
        if (Array.isArray(value)) return value.map(v => String(v));
        if (value && typeof value === 'object') return Object.keys(value);
        if (typeof value === 'string' && value.trim()) return [value.trim()];
        return [];
    }

    function extractAgentList(payload) {
        if (Array.isArray(payload)) return payload;
        if (payload && Array.isArray(payload.agents)) return payload.agents;
        if (payload && Array.isArray(payload.registered_agents)) return payload.registered_agents;
        if (payload && Array.isArray(payload.local_agents)) return payload.local_agents;
        return [];
    }

    function formatDuration(seconds) {
        const secs = Math.max(0, Number(seconds) || 0);
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        return h > 0 ? `${h}h ${m}m` : `${m}m`;
    }

    function formatTokenBalance(balance) {
        if (!balance) return '--';
        const amount = Number(balance.amount ?? balance.value ?? null);
        const decimals = Number(balance.decimals ?? 0);
        const symbol = String(balance.symbol || '').trim();
        if (!Number.isFinite(amount) || !Number.isFinite(decimals)) return '--';
        const divisor = Math.pow(10, Math.max(0, decimals));
        const value = divisor ? amount / divisor : amount;
        const fixed = value >= 100 ? value.toFixed(2) : value >= 1 ? value.toFixed(3) : value.toFixed(4);
        return symbol ? `${fixed} ${symbol}` : fixed;
    }

    function appendSessionLog(message, tone = 'info') {
        const log = document.getElementById('sessionLog');
        if (!log) return;
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (tone === 'warn') entry.style.color = 'var(--accent-gold)';
        if (tone === 'error') entry.style.color = 'var(--accent-red)';
        entry.innerHTML = `<span class="log-time">${time}</span> <span>${escapeHtml(message)}</span>`;
        log.prepend(entry);
        while (log.children.length > 50) {
            log.removeChild(log.lastChild);
        }
        const placeholder = Array.from(log.querySelectorAll('.log-entry')).find(entry => (entry.querySelector('.log-time')?.textContent || '') === '--:--');
        if (placeholder && log.children.length > 1) {
            placeholder.remove();
        }
    }

    function renderTaskOverview(tasks) {
        lastTasks = tasks;
        const columns = {
            todo: document.querySelector('#task-overview .task-overview-col[data-col="todo"]'),
            progress: document.querySelector('#task-overview .task-overview-col[data-col="progress"]'),
            done: document.querySelector('#task-overview .task-overview-col[data-col="done"]'),
        };
        const grouped = { todo: [], progress: [], done: [] };
        tasks.forEach(t => {
            const col = taskColumnId(t.status);
            grouped[col].push(t);
        });
        Object.entries(columns).forEach(([key, col]) => {
            if (!col) return;
            const header = col.querySelector('h4');
            const list = col.querySelector('.task-overview-items');
            if (!header || !list) return;
            const items = grouped[key];
            header.textContent = `${key === 'progress' ? 'In Progress' : key === 'done' ? 'Done' : 'Todo'} (${items.length})`;
            list.innerHTML = '';
            if (items.length === 0) {
                list.innerHTML = '<div class="task-overview-item" style="color:var(--text-muted);">No tasks</div>';
                return;
            }
            items.slice(0, 3).forEach(task => {
                const div = document.createElement('div');
                div.className = 'task-overview-item';

                const titleEl = document.createElement('div');
                titleEl.style.fontWeight = '600';
                titleEl.style.marginBottom = '4px';

                const metaEl = document.createElement('div');
                metaEl.style.fontSize = '11px';
                metaEl.style.color = 'var(--text-muted)';

                const metaText = `${task.priority || 'Normal'}  - ${task.assignee || 'Unassigned'}`;
                setTranslatedText(titleEl, task.title || '');
                setTranslatedText(metaEl, metaText);

                div.appendChild(titleEl);
                div.appendChild(metaEl);
                list.appendChild(div);
            });
        });
    }

    function renderMemoryOverview(memory) {
        if (!memory) return;
        const fragCount = Object.values(memory.tiers || {}).reduce((sum, list) => sum + ((list || []).length), 0);
        const lessonCount = (memory.lessons && Array.isArray(memory.lessons.lessons)) ? memory.lessons.lessons.length : 0;
        const fragmentsEl = document.getElementById('memory-fragments');
        const fragmentsLabel = document.getElementById('memory-fragments-label');
        const lessonsPill = document.getElementById('memory-lessons-pill');
        const distEl = document.getElementById('memory-distillation');
        if (fragmentsEl) fragmentsEl.textContent = `+${fragCount}`;
        if (fragmentsLabel) fragmentsLabel.textContent = fragCount === 1 ? 'New fragment' : 'New fragments';
        if (lessonsPill) lessonsPill.innerHTML = `<i class="fa-solid fa-graduation-cap"></i> ${lessonCount} Lessons`;
        if (distEl) distEl.innerHTML = `<i class="fa-solid fa-clock"></i> SOUL synced`;
    }

    function renderMemoryTiers(memory) {
        if (!memory) return;
        const rules = memory.core?.absolute_rules || [];
        const relationships = memory.core?.relationships || {};
        const coreItems = 1 + rules.length + Object.keys(relationships).length;
        const tierCounts = {
            core: coreItems,
            m30: (memory.tiers?.m30 || []).length,
            m90: (memory.tiers?.m90 || []).length,
            m365: (memory.tiers?.m365 || []).length,
            lessons: (memory.lessons?.lessons || []).length,
        };

        const metaLabels = {
            core: `${tierCounts.core} items - SOUL & Rules`,
            m30: `${tierCounts.m30} items - Recent Context`,
            m90: `${tierCounts.m90} items - Project Knowledge`,
            m365: `${tierCounts.m365} items - Hardened Facts`,
            lessons: `${tierCounts.lessons} Extracted Patterns`,
        };

        Object.entries(metaLabels).forEach(([tier, text]) => {
            const el = document.querySelector(`.tier-meta[data-tier-meta="${tier}"]`);
            if (el) el.textContent = text;
        });

        const overview = document.getElementById('memoryOverview');
        if (overview) {
            const totalTiered = tierCounts.m30 + tierCounts.m90 + tierCounts.m365;
            overview.innerHTML = `Rules: ${rules.length}<br>Lessons: ${tierCounts.lessons}<br>Tiered memories: ${totalTiered}`;
        }
    }

    //     Memory Knowledge Graph (Canvas Force-Directed)                       
    let graphNodes = [];
    let graphEdges = [];
    let graphAnimId = null;
    let graphForceMode = true;
    let graphDrag = null;

    const GRAPH_TIER_COLORS = {
        core:    '#a5b4fc',
        m30:     '#6ee7b7',
        m90:     '#fcd34d',
        m365:    '#f87171',
        lessons: '#c084fc',
    };

    function buildGraphData(memory) {
        const nodes = [];
        const edges = [];
        let id = 0;

        // Core node
        nodes.push({ id: id++, label: 'SOUL', tier: 'core', r: 18 });

        // Rules as nodes connected to SOUL
        const rules = memory.core?.absolute_rules || [];
        rules.forEach((rule, i) => {
            const rId = id++;
            const short = rule.length > 30 ? rule.slice(0, 30) + '...' : rule;
            nodes.push({ id: rId, label: `Rule ${i+1}`, detail: short, tier: 'core', r: 10 });
            edges.push({ from: 0, to: rId });
        });

        // Relationships
        const rels = memory.core?.relationships || {};
        Object.keys(rels).forEach(key => {
            const rId = id++;
            nodes.push({ id: rId, label: key, tier: 'core', r: 12 });
            edges.push({ from: 0, to: rId });
        });

        // Tiered memories
        ['m30', 'm90', 'm365'].forEach(tier => {
            const items = memory.tiers?.[tier] || [];
            const hubId = id++;
            nodes.push({ id: hubId, label: tier.toUpperCase(), tier, r: 15 });
            edges.push({ from: 0, to: hubId });
            items.slice(0, 15).forEach(item => {
                const nId = id++;
                const text = typeof item === 'string' ? item : (item.content || '');
                const lbl = text.length > 25 ? text.slice(0,25)+'...' : (text || `${tier} item`);
                nodes.push({ id: nId, label: lbl, detail: text.length > 25 ? text : null, tier, r: 8 });
                edges.push({ from: hubId, to: nId });
            });
        });

        // Lessons
        const lessons = memory.lessons?.lessons || [];
        if (lessons.length > 0) {
            const lhub = id++;
            nodes.push({ id: lhub, label: 'Lessons', tier: 'lessons', r: 15 });
            edges.push({ from: 0, to: lhub });
            lessons.slice(0, 10).forEach(lesson => {
                const nId = id++;
                const text = typeof lesson === 'string' ? lesson : (lesson.pattern || lesson.title || '');
                const lbl = text.length > 25 ? text.slice(0,25)+'...' : (text || 'lesson');
                nodes.push({ id: nId, label: lbl, detail: `Efficacy: ${lesson.effectiveness || '?'}`, tier: 'lessons', r: 8 });
                edges.push({ from: lhub, to: nId });
            });
        }

        return { nodes, edges };
    }

    async function renderMemoryGraph(memory) {
        const canvas = document.getElementById('memoryGraphCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.width = canvas.clientWidth * (window.devicePixelRatio || 1);
        const H = canvas.height = canvas.clientHeight * (window.devicePixelRatio || 1);
        ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
        const cW = canvas.clientWidth, cH = canvas.clientHeight;

        let data;
        try {
            const res = await apiFetch(`${API}/api/memory/graph`);
            if (res.ok) {
                const backendData = await res.json();
                // Map backend format (source/target) to buildGraphData format if needed
                // handle_memory_graph returns nodes: [{id, label, type, size}], edges: [{source, target, weight}]
                data = {
                    nodes: backendData.nodes.map(n => ({
                        ...n,
                        tier: n.type,
                        r: n.size / (window.devicePixelRatio || 1)
                    })),
                    edges: backendData.edges.map(e => {
                        const fromIdx = backendData.nodes.findIndex(n => n.id === e.source);
                        const toIdx = backendData.nodes.findIndex(n => n.id === e.target);
                        return { from: fromIdx, to: toIdx, weight: e.weight };
                    })
                };
            } else {
                data = buildGraphData(memory);
            }
        } catch (e) {
            data = buildGraphData(memory);
        }

        graphNodes = data.nodes;
        graphEdges = data.edges;

        // Initialize positions
        graphNodes.forEach((n, i) => {
            if (i === 0) { n.x = cW / 2; n.y = cH / 2; }
            else {
                const angle = (i / graphNodes.length) * Math.PI * 2;
                const rad = 80 + Math.random() * 80;
                n.x = cW / 2 + Math.cos(angle) * rad;
                n.y = cH / 2 + Math.sin(angle) * rad;
            }
            n.vx = 0; n.vy = 0;
        });

        // Mouse interaction
        canvas.onmousedown = (e) => {
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left, my = e.clientY - rect.top;
            const hit = graphNodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.r + 4);
            if (hit) { graphDrag = hit; canvas.style.cursor = 'grabbing'; }
        };
        canvas.onmousemove = (e) => {
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left, my = e.clientY - rect.top;
            if (graphDrag) { graphDrag.x = mx; graphDrag.y = my; }
            // Tooltip
            const tip = document.getElementById('graphTooltip');
            const hover = graphNodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.r + 4);
            if (hover && tip) {
                tip.style.display = 'block';
                tip.style.left = (mx + 14) + 'px';
                tip.style.top  = (my - 10) + 'px';
                tip.innerHTML = `<b>${escapeHtml(hover.label)}</b>${hover.detail ? '<br>' + escapeHtml(hover.detail) : ''}<br><span style="color:${GRAPH_TIER_COLORS[hover.tier]}">${hover.tier}</span>`;
            } else if (tip) { tip.style.display = 'none'; }
        };
        canvas.onmouseup = () => { graphDrag = null; canvas.style.cursor = 'grab'; };
        canvas.onmouseleave = () => { graphDrag = null; const t = document.getElementById('graphTooltip'); if(t) t.style.display='none'; };

        if (graphAnimId) cancelAnimationFrame(graphAnimId);

        function tick() {
            ctx.clearRect(0, 0, cW, cH);

            if (graphForceMode) {
                // Simple force simulation
                graphNodes.forEach(a => {
                    graphNodes.forEach(b => {
                        if (a.id === b.id) return;
                        const dx = b.x - a.x, dy = b.y - a.y;
                        const dist = Math.max(Math.hypot(dx, dy), 1);
                        const repulsion = -300 / (dist * dist);
                        a.vx += (dx / dist) * repulsion;
                        a.vy += (dy / dist) * repulsion;
                    });
                });

                graphEdges.forEach(e => {
                    const a = graphNodes[e.from], b = graphNodes[e.to];
                    if (!a || !b) return;
                    const dx = b.x - a.x, dy = b.y - a.y;
                    const dist = Math.hypot(dx, dy);
                    const force = (dist - 80) * 0.005;
                    const fx = (dx / (dist||1)) * force;
                    const fy = (dy / (dist||1)) * force;
                    a.vx += fx; a.vy += fy;
                    b.vx -= fx; b.vy -= fy;
                });

                // Center gravity
                graphNodes.forEach(n => {
                    n.vx += (cW/2 - n.x) * 0.001;
                    n.vy += (cH/2 - n.y) * 0.001;
                });

                graphNodes.forEach(n => {
                    if (n === graphDrag) return;
                    n.vx *= 0.85; n.vy *= 0.85;
                    n.x += n.vx; n.y += n.vy;
                    n.x = Math.max(n.r, Math.min(cW - n.r, n.x));
                    n.y = Math.max(n.r, Math.min(cH - n.r, n.y));
                });
            }

            // Draw edges
            ctx.lineWidth = 1;
            ctx.strokeStyle = 'rgba(148,163,184,0.15)';
            graphEdges.forEach(e => {
                const a = graphNodes[e.from], b = graphNodes[e.to];
                if (!a || !b) return;
                ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
            });

            // Draw nodes
            graphNodes.forEach(n => {
                const color = GRAPH_TIER_COLORS[n.tier] || '#94a3b8';
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
                ctx.fillStyle = color + '33';
                ctx.fill();
                ctx.strokeStyle = color;
                ctx.lineWidth = 1.5;
                ctx.stroke();

                // Label
                if (n.r >= 10) {
                    ctx.fillStyle = '#e2e8f0';
                    ctx.font = `${Math.max(8, n.r * 0.65)}px Inter, sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    const maxLen = Math.floor(n.r * 0.6);
                    const lbl = n.label.length > maxLen + 2 ? n.label.slice(0, maxLen) + '...' : n.label;
                    ctx.fillText(lbl, n.x, n.y);
                }
            });

            graphAnimId = requestAnimationFrame(tick);
        }
        tick();
    }

    function resetGraphZoom() {
        if (lastMemory) renderMemoryGraph(lastMemory);
    }

    function toggleGraphMode() {
        graphForceMode = !graphForceMode;
        const btn = document.getElementById('graphModeBtn');
        if (btn) btn.innerHTML = graphForceMode
            ? '<i class="fa-solid fa-arrows-to-dot"></i> Force'
            : '<i class="fa-solid fa-grip"></i> Fixed';
    }

    function renderMemoryViewerFeed(memory) {
        const feed = document.getElementById('memoryViewerFeed');
        if (!feed) return;
        const entries = [];

        // Collect entries from all tiers
        ['m30', 'm90', 'm365'].forEach(tier => {
            const items = memory.tiers?.[tier] || [];
            items.forEach(item => {
                const text = typeof item === 'string' ? item : (item.content || item.title || JSON.stringify(item));
                entries.push({ text, tier, ts: item.timestamp || null });
            });
        });

        // Lessons
        (memory.lessons?.lessons || []).forEach(l => {
            const text = typeof l === 'string' ? l : (l.title || l.content || '');
            entries.push({ text, tier: 'lessons', ts: l.timestamp || null });
        });

        if (entries.length === 0) {
            feed.innerHTML = '<div style="font-size:12px; color:var(--text-muted); padding:16px; text-align:center;">No memory entries yet</div>';
            return;
        }

        const tierColors = { m30: '#6ee7b7', m90: '#fcd34d', m365: '#f87171', lessons: '#c084fc', core: '#a5b4fc' };
        feed.innerHTML = entries.slice(0, 12).map(e => {
            const color = tierColors[e.tier] || '#94a3b8';
            const shortText = e.text.length > 80 ? e.text.slice(0, 80) + '...' : e.text;
            const timeStr = e.ts ? new Date(e.ts).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) : '';
            return `
                <div style="padding:10px 12px; background:var(--surface-800); border-radius:10px; border-left:3px solid ${color}; cursor:pointer;" class="mem-feed-item">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="font-size:12px; font-weight:600; color:var(--text-primary);">${escapeHtml(shortText.split(' ').slice(0,5).join(' '))}</span>
                        <span style="font-size:10px; color:var(--text-muted);">${timeStr}</span>
                    </div>
                    <div style="font-size:11px; color:var(--text-muted); line-height:1.3;">${escapeHtml(shortText)}</div>
                    <div style="font-size:10px; color:${color}; margin-top:4px;">${e.tier.toUpperCase()}</div>
                </div>
            `;
        }).join('');
    }

    function renderMemoryPopularNodes(memory) {
        const pop = document.getElementById('memPopularNodes');
        const tracker = document.getElementById('memAgentTracker');
        if (!pop) return;

        const rules = memory.core?.absolute_rules || [];
        const m30 = memory.tiers?.m30 || [];
        const lessons = memory.lessons?.lessons || [];

        // Left card: top memory items
        const topItems = [...m30.slice(0,3), ...rules.slice(0,2)];
        pop.innerHTML = `
            <h5 style="font-size:12px; font-weight:600; margin:0 0 8px;">Top Memories</h5>
            ${topItems.length > 0 ? topItems.map(item => {
                const txt = typeof item === 'string' ? item : (item.content || '');
                return `<div style="font-size:11px; color:var(--text-muted); padding:4px 0; border-bottom:1px solid var(--surface-700);">${escapeHtml(txt.slice(0,40))}</div>`;
            }).join('') : '<div style="font-size:11px; color:var(--text-muted);">No data</div>'}
        `;

        // Right card: agent tracker
        if (tracker) {
            tracker.innerHTML = `
                <h5 style="font-size:12px; font-weight:600; margin:0 0 8px;">Agent Tracker</h5>
                <div style="font-size:11px; color:var(--text-muted);">
                    <div style="padding:4px 0;"><i class="fa-solid fa-robot" style="margin-right:4px; color:var(--accent-green);"></i> ${selectedAgentName || 'local'}</div>
                    <div style="padding:4px 0;"><i class="fa-solid fa-brain" style="margin-right:4px; color:var(--primary-400);"></i> ${rules.length} rules</div>
                    <div style="padding:4px 0;"><i class="fa-solid fa-graduation-cap" style="margin-right:4px; color:var(--accent-purple);"></i> ${lessons.length} lessons</div>
                </div>
            `;
        }
    }

    async function renderMemoryStorage(memory) {
        try {
            const res = await apiFetch(`${API}/api/memory/storage`);
            if (res.ok) {
                const stats = await res.json();
                const vec = document.getElementById('memStorageVector');
                const local = document.getElementById('memStorageLocal');
                const total = document.getElementById('memStorageTotal');
                
                if (vec) vec.textContent = `${stats.total_entries || 0} entries`;
                if (local) {
                    const kb = ((stats.memory_file_size_bytes || 0) / 1024).toFixed(1);
                    local.textContent = `${kb} KB stored`;
                }
                if (total) total.textContent = `${stats.lessons_count || 0} patterns`;
            }
        } catch (e) {
            // Fallback to memory tiers if storage API fails
            const totalItems = (memory.tiers?.m30?.length || 0) + (memory.tiers?.m90?.length || 0) + (memory.tiers?.m365?.length || 0);
            const vec = document.getElementById('memStorageVector');
            if (vec) vec.textContent = `${totalItems} entries`;
        }
    }

    function switchMemoryTab(btn, mode) {
        document.querySelectorAll('#view-memory .tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        const graphView = document.getElementById('memory-graph-view');
        const recentView = document.getElementById('memory-recent-view');
        const docsView = document.getElementById('memory-docs-view');
        const popularSect = document.getElementById('graph-popular-sections');
        
        if (graphView) graphView.style.display = 'none';
        if (recentView) recentView.style.display = 'none';
        if (docsView) docsView.style.display = 'none';
        if (popularSect) popularSect.style.display = 'none';

        if (mode === 'graph') {
            if (graphView) graphView.style.display = 'block';
            if (popularSect) popularSect.style.display = 'grid';
            if (lastMemory) renderMemoryGraph(lastMemory);
        } else if (mode === 'recent') {
            if (recentView) recentView.style.display = 'flex';
            renderRecentMemories();
        } else if (mode === 'docs') {
            if (docsView) docsView.style.display = 'flex';
        }
        
        showToast(`Memory view: ${mode}`, 'info');
    }

    function renderRecentMemories() {
        const list = document.getElementById('memoryRecentList');
        if (!list) return;

        if (!lastMemory || !lastMemory.tiers) {
            list.innerHTML = '<div style="padding:20px; text-align:center; color:var(--text-muted);">No entries loaded</div>';
            return;
        }

        // Collect all entries from tiers
        let entries = [];
        Object.keys(lastMemory.tiers).forEach(t => {
            lastMemory.tiers[t].forEach(e => {
                entries.push({ ...e, tier: t });
            });
        });

        // Sort by timestamp (if available) - mocking for now
        entries.sort((a, b) => (b.time || 0) - (a.time || 0));

        list.innerHTML = entries.map(e => `
            <div class="card" style="padding:10px; cursor:pointer;" onclick="selectMemoryNode('${e.id}')">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-weight:600; font-size:12px;">${e.id}</span>
                    <span class="badge" style="font-size:10px;">${e.tier}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); margin-top:4px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                    ${e.content || 'Memory object entry'}
                </div>
            </div>
        `).join('');
    }


    function getActiveMemoryTier() {
        const active = document.querySelector('.tier-item.active');
        return active?.dataset.tier || 'core';
    }

    function memoryTitleForTier(tier) {
        switch (tier) {
            case 'core':
                return 'SOUL.md';
            case 'm30':
                return 'M30 Short-term';
            case 'm90':
                return 'M90 Mid-term';
            case 'm365':
                return 'M365 Long-term';
            case 'lessons':
                return 'Lessons';
            default:
                return 'Memory';
        }
    }

    function normalizeActivityTag(tag) {
        if (!tag) return 'activity';
        return String(tag)
            .replace(/([a-z])([A-Z])/g, '$1_$2')
            .replace(/\s+/g, '_')
            .toLowerCase();
    }

    function getActivityType(entry) {
        const at = entry?.activity_type;
        if (!at) return { tag: 'activity', data: null };
        if (typeof at.type === 'string') {
            return { tag: normalizeActivityTag(at.type), data: at };
        }
        const keys = Object.keys(at);
        if (keys.length > 0) {
            const key = keys[0];
            return { tag: normalizeActivityTag(key), data: at[key] };
        }
        return { tag: 'activity', data: at };
    }

    function getCustomActivity(entry) {
        const at = entry?.activity_type;
        if (!at) return null;
        if (at.Custom) return at.Custom;
        if (typeof at.type === 'string' && normalizeActivityTag(at.type) === 'custom') return at;
        return null;
    }

    function activityLabel(entry) {
        if (!entry) return 'Activity';
        if (entry.summary) return entry.summary;
        if (entry.content) return entry.content;
        const info = getActivityType(entry);
        return info.tag ? info.tag.replace(/_/g, ' ') : 'Activity';
    }
    function renderEconomy(status) {
        lastStatus = status;
        const cpu = Number(status?.cpu_usage ?? 0);
        const mem = Number(status?.memory_percent ?? 0);
        const caps = Number(status?.capabilities ?? 0);
        const uptime = Number(status?.uptime_secs ?? 0);
        const econVal = document.getElementById('economy-metric');
        const econSub = document.getElementById('economy-subtitle');
        const econCap = document.getElementById('economy-capabilities');
        const econUp = document.getElementById('economy-uptime');
        const balance = document.getElementById('balance-display');
        if (econVal) econVal.textContent = `${mem.toFixed(1)}%`;
        if (econSub) econSub.textContent = 'Memory usage';
        if (econCap) econCap.textContent = `Capabilities ${caps}/17`;
        if (econUp) econUp.innerHTML = `<i class="fa-solid fa-handshake"></i> Uptime ${formatDuration(uptime)}`;
        if (balance) balance.innerHTML = `<i class="fa-solid fa-microchip"></i> v${escapeHtml(status?.version || '?')}  - CPU ${cpu.toFixed(1)}%`;

        renderMarketStats(status);
    }

    function renderMarketStats(status) {
        const mcStatRuns = document.getElementById('marketStatRuns');
        const mcStatActive = document.getElementById('marketStatActive');
        const mcStatRating = document.getElementById('marketStatRating');
        const mcStatBalance = document.getElementById('marketStatBalance');

        const onlineAgents = cachedAgents.filter(a => normalizeAgentStatus(a.status) === 'online');
        const totalRuns = lastMarketStats?.runs_total
            ?? lastActivityStats?.entries_by_type?.command_exec
            ?? lastActivityStats?.total_entries
            ?? null;
        const ratingValue = lastMarketStats?.rating ?? lastMarketStats?.reputation_score ?? null;
        const ratingNum = Number(ratingValue);
        const balanceValue = lastMarketStats?.balance ?? null;

        if (mcStatRuns) mcStatRuns.textContent = totalRuns != null ? String(totalRuns) : '--';
        if (mcStatActive) mcStatActive.textContent = onlineAgents.length;
        if (mcStatRating) mcStatRating.textContent = Number.isFinite(ratingNum) ? ratingNum.toFixed(1) : '--';
        if (mcStatBalance) {
            const fallback = status?.balance ?? status?.sui_balance ?? null;
            mcStatBalance.textContent = balanceValue ? formatTokenBalance(balanceValue) : (fallback != null ? `${fallback} SUI` : '--');
        }

        const localOnline = document.getElementById('stat-local-online');
        const remoteOnline = document.getElementById('stat-remote-online');
        const maxAgents = document.getElementById('stat-max-agents');

        const localOnlineCount = cachedAgents.filter(a => String(a.source || '').toLowerCase() === 'local' && normalizeAgentStatus(a.status) === 'online').length;
        const remoteOnlineCount = cachedAgents.filter(a => String(a.source || '').toLowerCase() === 'remote' && normalizeAgentStatus(a.status) === 'online').length;
        const maxAgentsValue = lastAgentsSummary?.max_agents_for_tier
            ?? lastAgentsSummary?.max_agents
            ?? lastAgentsSummary?.active_agents_total
            ?? cachedAgents.length;

        if (localOnline) localOnline.textContent = localOnlineCount;
        if (remoteOnline) remoteOnline.textContent = remoteOnlineCount;
        if (maxAgents) maxAgents.textContent = maxAgentsValue;
    }

    function highlightSidebarSelection() {
        document.querySelectorAll('#sidebarDeviceGroups .device-item').forEach(item => {
            item.classList.toggle('active', item.dataset.agentId === selectedAgentId);
        });
    }

    function renderSidebarAgents(localAgents, remoteAgents) {
        const container = document.getElementById('sidebarDeviceGroups');
        if (!container) return;

        const localHtml = localAgents.map(agent => `
            <div class="device-item" data-agent-id="${agent.id}" data-agent-name="${agent.name}">
                <div class="status-dot ${normalizeAgentStatus(agent.status) === 'online' ? 'online' : 'offline'}"></div>
                <span>${agent.name}</span>
            </div>
        `).join('');

        const onlineRemote = remoteAgents.filter(agent => normalizeAgentStatus(agent.status) === 'online');
        const remoteSection = onlineRemote.length > 0
            ? `
                <div class="group-title" style="margin:14px 0 8px 0;"><span>Remote Registry (${onlineRemote.length})</span></div>
                ${onlineRemote.map(agent => `
                    <div class="device-item" data-agent-id="${agent.id}" data-agent-name="${agent.name}">
                        <div class="status-dot ${normalizeAgentStatus(agent.status) === 'online' ? 'online' : 'offline'}"></div>
                        <span>${agent.name}</span>
                    </div>
                `).join('')}
            `
            : '';
        container.innerHTML = localHtml + remoteSection;
        container.querySelectorAll('.device-item span').forEach(span => setTranslatedText(span, span.textContent));
        const title = document.getElementById('sidebarGroupTitle');
        if (title) title.textContent = `Local Agents (${localAgents.length})`;
        highlightSidebarSelection();
    }

    function renderActiveAgents(localAgents) {
        const listEl = document.getElementById('activeAgentsList');
        const countEl = document.getElementById('activeAgentsCount');
        const topbarEl = document.getElementById('topbarActiveAgents');
        if (!listEl || !countEl || !topbarEl) return;

        if (localAgents.length === 0) {
            listEl.innerHTML = '<div style="color:var(--text-muted); font-size:12px;">No local agents available.</div>';
            countEl.textContent = '0';
            topbarEl.innerHTML = '<i class="fa-solid fa-server"></i> 0 Agent Active';
            return;
        }

        listEl.innerHTML = localAgents.map((agent, idx) => {
            const utilization = 55 + ((idx * 17) % 40);
            return `
                <div class="agent-list-item">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <div class="status-dot ${normalizeAgentStatus(agent.status) === 'online' ? 'online' : 'offline'}"></div>
                        <div>
                            <div style="font-weight:600">${agent.name}</div>
                            <div style="font-size:11px; color:var(--text-muted)">Profile: ${agent.profile || 'worker'}</div>
                        </div>
                    </div>
                    <div style="text-align:right">
                        <div style="font-family:var(--font-mono); font-size:11px; margin-bottom:4px">${utilization}%</div>
                        <div class="progress-bar"><div class="progress-fill" style="width:${utilization}%"></div></div>
                    </div>
                </div>
            `;
        }).join('');

        countEl.textContent = `${localAgents.length}`;
        topbarEl.innerHTML = `<i class="fa-solid fa-server"></i> ${localAgents.length} Agent${localAgents.length > 1 ? 's' : ''} Active`;
    }

    async function refreshAgentsUI() {
        try {
            const res = await apiFetch(`${API}/api/agents`);
            if (!res.ok) return;
            const data = await res.json();
            const showOffline = document.getElementById('marketShowOffline')?.checked;

            const localAgents = data.local_agents || [];
            const remoteAgents = data.registered_agents || data.agents || [];
            lastAgentsSummary = data;
            cachedAgents = [...localAgents, ...remoteAgents.filter(ra => !localAgents.some(la => la.id === ra.id))];

            const statLocal = document.getElementById('stat-local-online');
            const statRemote = document.getElementById('stat-remote-online');
            const statMax = document.getElementById('stat-max-agents');
            const onlineRemote = remoteAgents.filter(a => normalizeAgentStatus(a.status) === 'online').length;
            if (statLocal) statLocal.textContent = `${localAgents.length}`;
            if (statRemote) statRemote.textContent = `${onlineRemote}`;
            if (statMax) statMax.textContent = `${data.max_agents_for_tier || data.max_agents || data.active_agents_total || cachedAgents.length}`;

            if (!cachedAgents.some(agent => agent.id === selectedAgentId)) {
                selectedAgentId = localAgents[0]?.id || 'local';
            }
            const selected = cachedAgents.find(agent => agent.id === selectedAgentId);
            selectedAgentName = selected ? selected.name : selectedAgentId;

            renderSidebarAgents(localAgents, remoteAgents);
            renderActiveAgents(localAgents);
            renderAgentFleetStrip(cachedAgents);
            renderAgentTopology(cachedAgents);
            renderMarketStats(lastStatus);
        } catch (e) {
            console.error('Failed to refresh agents:', e);
        }
    }

    //     Agent Board: Fleet Strip + Topology                                  
    function renderAgentFleetStrip(agents) {
        const strip = document.getElementById('agentFleetStrip');
        if (!strip) return;
        if (!agents || agents.length === 0) {
            strip.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:20px;">No agents found. Use "Create Agent" or "Discover".</div>';
            return;
        }
        strip.innerHTML = agents.map(a => {
            const isOnline = normalizeAgentStatus(a.status) === 'online';
            const isSelected = a.id === selectedAgentId;
            return `
                <div onclick="selectAgentDetail('${escapeHtml(a.id || '')}')" style="min-width:140px; padding:12px 16px; background:${isSelected ? 'linear-gradient(135deg, rgba(99,102,241,0.2), rgba(168,85,247,0.15))' : 'var(--surface-800)'}; border:1px solid ${isSelected ? 'var(--primary-500)' : 'var(--surface-700)'}; border-radius:12px; cursor:pointer; transition:all 0.2s; text-align:center;">
                    <div style="font-size:20px; margin-bottom:6px;"> </div>
                    <div style="font-size:12px; font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(a.name || a.id || 'Agent')}</div>
                    <div style="font-size:10px; color:${isOnline ? 'var(--accent-green)' : 'var(--text-muted)'}; margin-top:4px;"> - ${isOnline ? 'Online' : 'Offline'}</div>
                </div>
            `;
        }).join('');
    }

    function selectAgentDetail(agentId) {
        selectedAgentId = agentId;
        const agent = cachedAgents.find(a => a.id === agentId);
        if (!agent) return;
        selectedAgentName = agent.name || agentId;

        // Header
        const nameEl = document.getElementById('agentDetailName');
        const metaEl = document.getElementById('agentDetailMeta');
        const statusEl = document.getElementById('agentDetailStatus');
        if (nameEl) nameEl.textContent = agent.name || agentId;
        if (metaEl) metaEl.textContent = `${agent.address || '127.0.0.1'}:${agent.port || '-'}   ${agent.profile || 'Worker'}   ${agent.source || 'local'}`;
        if (statusEl) {
            statusEl.style.display = 'inline-flex';
            const isOnline = normalizeAgentStatus(agent.status) === 'online';
            statusEl.className = isOnline ? 'badge badge-green' : 'badge badge-gold';
            statusEl.textContent = isOnline ? 'Online' : 'Offline';
        }

        // Capabilities
        const capsList = document.getElementById('agentCapsList');
        const caps = normalizeCapabilities(agent.capabilities);
        if (capsList) {
            capsList.innerHTML = caps.length > 0
                ? caps.map(c => `<div style="display:flex; align-items:center; gap:8px; font-size:12px;"><i class="fa-solid fa-check-circle" style="color:var(--accent-green); font-size:10px;"></i> ${escapeHtml(c)}</div>`).join('')
                : '<div style="font-size:12px; color:var(--text-muted);">No capabilities</div>';
        }

        // Resources
        const cpu = document.getElementById('agentResCpu');
        const ram = document.getElementById('agentResRam');
        const tasks = document.getElementById('agentResTasks');
        const uptime = document.getElementById('agentResUptime');
        if (cpu) cpu.textContent = (agent.cpu_usage || lastStatus?.cpu_usage || 0).toFixed(1) + '%';
        if (ram) ram.textContent = (agent.memory_percent || lastStatus?.memory_percent || 0).toFixed(0) + '%';
        if (tasks) tasks.textContent = agent.tasks || lastStatus?.active_tasks || 0;
        if (uptime) uptime.textContent = formatUptime(agent.uptime_secs || lastStatus?.uptime_secs || 0);

        loadAgentProfileDetails(agentId, agent);

        // Re-render strips to show selection
        renderAgentFleetStrip(cachedAgents);
        renderAgentTopology(cachedAgents);
        updateContextPanel(agentId, 'Agent');
    }

    async function fetchAgentProfile(agentId) {
        try {
            const res = await apiFetch(`${API}/api/agents/${agentId}`);
            if (!res.ok) return null;
            return await res.json();
        } catch (_) {
            return null;
        }
    }

    async function fetchAgentMetrics(agentId) {
        try {
            const res = await apiFetch(`${API}/api/agents/${agentId}/metrics`, { cache: 'no-store' });
            if (!res.ok) return null;
            return await res.json();
        } catch (_) {
            return null;
        }
    }

    function applyAgentMetrics(metrics) {
        const cpuEl = document.getElementById('agentResCpu');
        const ramEl = document.getElementById('agentResRam');
        const uptimeEl = document.getElementById('agentResUptime');
        const latencyEl = document.getElementById('agentResLatency');

        const cpuVal = metrics?.cpu_pct ?? metrics?.cpu_usage ?? null;
        const ramVal = metrics?.ram_pct ?? metrics?.memory_percent ?? null;
        const uptimeVal = metrics?.uptime_secs ?? null;
        const latencyVal = metrics?.latency_ms ?? null;

        const cpuNum = Number(cpuVal);
        const ramNum = Number(ramVal);
        if (cpuEl && Number.isFinite(cpuNum)) cpuEl.textContent = `${cpuNum.toFixed(1)}%`;
        if (ramEl && Number.isFinite(ramNum)) ramEl.textContent = `${ramNum.toFixed(0)}%`;
        if (uptimeEl && uptimeVal != null) uptimeEl.textContent = formatUptime(uptimeVal);
        if (latencyEl && latencyVal != null) latencyEl.textContent = `${latencyVal}ms`;
    }

    function applyAgentProfileDetails(agentId, profile, fallbackAgent) {
        const cpuEl = document.getElementById('agentResCpu');
        const ramEl = document.getElementById('agentResRam');
        const tasksEl = document.getElementById('agentResTasks');
        const uptimeEl = document.getElementById('agentResUptime');
        const latencyEl = document.getElementById('agentResLatency');

        const cpuVal = profile?.system?.cpu ?? fallbackAgent?.cpu_usage ?? lastStatus?.cpu_usage ?? null;
        const ramVal = profile?.system?.memory ?? fallbackAgent?.memory_percent ?? lastStatus?.memory_percent ?? null;
        const uptimeVal = profile?.uptime_secs ?? fallbackAgent?.uptime_secs ?? lastStatus?.uptime_secs ?? null;
        const taskPool = Array.isArray(profile?.recent_tasks)
            ? profile.recent_tasks
            : (lastTasks || []).filter(t => t.assignee === agentId || t.assignee === fallbackAgent?.name);
        const latencyVal = profile?.latency_ms ?? null;

        if (cpuEl) cpuEl.textContent = cpuVal != null ? `${Number(cpuVal).toFixed(1)}%` : '--';
        if (ramEl) ramEl.textContent = ramVal != null ? `${Number(ramVal).toFixed(0)}%` : '--';
        if (tasksEl) tasksEl.textContent = taskPool ? String(taskPool.length) : '--';
        if (uptimeEl) uptimeEl.textContent = uptimeVal != null ? formatUptime(uptimeVal) : '--';
        if (latencyEl) latencyEl.textContent = latencyVal != null ? `${latencyVal}ms` : '--';

        const capsList = document.getElementById('agentCapsList');
        if (capsList) {
            const caps = normalizeCapabilities(profile?.capabilities || fallbackAgent?.capabilities || []);
            capsList.innerHTML = caps.length > 0
                ? caps.map(c => `<div style="font-size:11px; padding:6px 10px; background:var(--surface-700); border-radius:6px;"><i class="fa-solid fa-check-circle" style="color:var(--accent-green); margin-right:6px;"></i> ${escapeHtml(c)}</div>`).join('')
                : '<div style="font-size:12px; color:var(--text-muted);">No capabilities</div>';
        }

        const missionList = document.getElementById('agentMissionsList');
        if (missionList) {
            const missions = taskPool ? taskPool.slice(0, 3) : [];
            if (!missions.length) {
                missionList.innerHTML = '<div style="font-size:12px; color:var(--text-muted); padding:10px;">No active missions</div>';
            } else {
                missionList.innerHTML = missions.map(m => `
                    <div style="padding:10px; background:var(--surface-800); border-radius:8px; border-left:3px solid var(--primary-500);">
                        <div style="font-size:12px; font-weight:600; margin-bottom:4px;">${escapeHtml(m.title || 'Task')}</div>
                        <div style="font-size:10px; color:var(--text-muted);">${escapeHtml(m.status || '')}</div>
                    </div>
                `).join('');
            }
        }
    }

    async function loadAgentProfileDetails(agentId, fallbackAgent) {
        const profile = await fetchAgentProfile(agentId);
        if (profile) {
            const nameEl = document.getElementById('agentDetailName');
            const metaEl = document.getElementById('agentDetailMeta');
            const statusEl = document.getElementById('agentDetailStatus');
            if (nameEl) nameEl.textContent = profile.name || fallbackAgent?.name || agentId;
            if (metaEl) metaEl.textContent = `${profile.profile || fallbackAgent?.profile || 'Worker'}  - ${profile.address || fallbackAgent?.address || '127.0.0.1'}:${profile.port || fallbackAgent?.port || '-'}`;
            if (statusEl) {
                statusEl.style.display = 'inline-block';
                statusEl.textContent = profile.status || fallbackAgent?.status || 'offline';
                statusEl.className = `badge ${normalizeAgentStatus(profile.status || fallbackAgent?.status) === 'online' ? 'badge-green' : 'badge-gold'}`;
            }
        }
        applyAgentProfileDetails(agentId, profile, fallbackAgent);
        const metrics = await fetchAgentMetrics(agentId);
        if (metrics) applyAgentMetrics(metrics);
    }

    function renderAgentTopology(agents) {
        const canvas = document.getElementById('agentGraphCanvas');
        if (!canvas || !agents || agents.length === 0) return;
        const ctx = canvas.getContext('2d');
        const dpr = window.devicePixelRatio || 1;
        canvas.width = canvas.clientWidth * dpr;
        canvas.height = canvas.clientHeight * dpr;
        ctx.scale(dpr, dpr);
        const cW = canvas.clientWidth, cH = canvas.clientHeight;
        ctx.clearRect(0, 0, cW, cH);

        // Draw network bg
        ctx.strokeStyle = 'rgba(99,102,241,0.06)';
        ctx.lineWidth = 0.5;
        for (let x = 0; x < cW; x += 40) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, cH); ctx.stroke(); }
        for (let y = 0; y < cH; y += 40) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(cW, y); ctx.stroke(); }

        // Position nodes
        const nodes = agents.map((a, i) => {
            const angle = (i / agents.length) * Math.PI * 2 - Math.PI / 2;
            const rx = Math.min(cW, cH) * 0.32;
            return {
                x: cW / 2 + Math.cos(angle) * rx,
                y: cH / 2 + Math.sin(angle) * rx,
                r: a.id === selectedAgentId ? 26 : 18,
                agent: a,
                online: normalizeAgentStatus(a.status) === 'online',
            };
        });

        // Edges (mesh)
        nodes.forEach((a, i) => {
            nodes.forEach((b, j) => {
                if (j <= i) return;
                ctx.strokeStyle = 'rgba(148,163,184,0.08)';
                ctx.lineWidth = 1;
                ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
            });
        });

        // Nodes
        nodes.forEach(n => {
            const selected = n.agent.id === selectedAgentId;
            // Glow
            if (n.online) {
                const grad = ctx.createRadialGradient(n.x, n.y, n.r * 0.5, n.x, n.y, n.r * 2.5);
                grad.addColorStop(0, selected ? 'rgba(99,102,241,0.25)' : 'rgba(16,185,129,0.12)');
                grad.addColorStop(1, 'transparent');
                ctx.fillStyle = grad;
                ctx.fillRect(n.x - n.r * 2.5, n.y - n.r * 2.5, n.r * 5, n.r * 5);
            }
            // Circle
            ctx.beginPath();
            ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
            ctx.fillStyle = selected ? 'rgba(99,102,241,0.3)' : (n.online ? 'rgba(16,185,129,0.15)' : 'rgba(100,116,139,0.1)');
            ctx.fill();
            ctx.strokeStyle = selected ? '#6366f1' : (n.online ? '#10b981' : '#475569');
            ctx.lineWidth = selected ? 2.5 : 1.5;
            ctx.stroke();

            // Robot icon (text)
            ctx.fillStyle = selected ? '#a5b4fc' : (n.online ? '#6ee7b7' : '#94a3b8');
            ctx.font = `${n.r * 0.7}px Inter, sans-serif`;
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText('🤖', n.x, n.y);

            // Label
            ctx.fillStyle = '#e2e8f0';
            ctx.font = `${selected ? 11 : 9}px Inter, sans-serif`;
            ctx.fillText(n.agent.name || n.agent.id || '', n.x, n.y + n.r + 12);
        });

        // Click handler
        canvas.onclick = (e) => {
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left, my = e.clientY - rect.top;
            const hit = nodes.find(n => Math.hypot(n.x - mx, n.y - my) < n.r + 6);
            if (hit) selectAgentDetail(hit.agent.id);
        };
    }

    // fetchAgentGraph moved to line 3196

    function toggleAgentViewTab(btn, mode) {
        document.querySelectorAll('#view-board .tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');

        const graphArea = document.getElementById('agent-graph-area');
        const listArea = document.getElementById('agent-list-area');
        const kanbanArea = document.getElementById('agent-kanban-area');

        if (graphArea) graphArea.style.display = 'none';
        if (listArea) listArea.style.display = 'none';
        if (kanbanArea) kanbanArea.style.display = 'none';

        if (mode === 'graph') {
            if (graphArea) graphArea.style.display = 'block';
            fetchAgentGraph();
        } else if (mode === 'list') {
            if (listArea) listArea.style.display = 'block';
            renderAgentList();
        } else if (mode === 'kanban') {
            if (kanbanArea) kanbanArea.style.display = 'block';
            fetchTasks(); // Kanban view is driven by Tasks
        }

        showToast(`Switched to ${mode} view`, 'info');
    }

    function renderAgentList() {
        const tbody = document.getElementById('agent-list-table-body');
        if (!tbody) return;

        if (!cachedAgents || cachedAgents.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="padding:40px; text-align:center; color:var(--text-muted);">No agents in fleet</td></tr>';
            return;
        }

        tbody.innerHTML = cachedAgents.map(a => `
            <tr style="border-bottom: 1px solid var(--surface-800);">
                <td style="padding:16px;">
                    <div style="display:flex; align-items:center; gap:12px;">
                        <div style="background:var(--surface-700); width:32px; height:32px; border-radius:8px; display:flex; align-items:center; justify-content:center;">
                            <i class="fa-solid fa-robot" style="font-size:14px; color:var(--primary-400);"></i>
                        </div>
                        <span style="font-weight:600;">${a.name}</span>
                    </div>
                </td>
                <td style="padding:16px;"><span class="badge ${a.status === 'online' ? 'badge-green' : 'badge-red'}">${a.status}</span></td>
                <td style="padding:16px; font-family:var(--font-mono); font-size:11px;">${a.id.substring(0, 16)}...</td>
                <td style="padding:16px;">${a.profile || 'Default'}</td>
                <td style="padding:16px; text-align:right;">
                    <button class="btn" onclick="inspectAgentModal('${a.id}')">Inspect</button>
                    <button class="btn" style="border-color:var(--accent-red); color:var(--accent-red);"><i class="fa-solid fa-power-off"></i></button>
                </td>
            </tr>
        `).join('');
    }

    function formatUptime(secs) {
        if (!secs || secs < 0) return '--';
        if (secs < 3600) return `${Math.floor(secs / 60)}m`;
        if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
        return `${Math.floor(secs / 86400)}d`;
    }

    function toggleMode() {
        const nextMode = currentMode === 'sanctum' ? 'market' : 'sanctum';
        setMode(nextMode);
        showToast(`Switched to ${nextMode.toUpperCase()} Mode`, 'info');
    }

    async function setMode(mode) {
        currentMode = mode;
        
        // Sync with backend
        try {
            await apiFetch(`${API}/api/agent/mode`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mode: mode })
            });
        } catch (e) {
            console.error("Failed to sync mode with backend:", e);
        }

        if (mode === 'market') {
            modeIndicator.className = 'mode-market';
            modeIndicator.style.borderColor = 'rgba(245, 158, 11, 0.4)';
            modeIndicator.style.background = 'rgba(245, 158, 11, 0.05)';
            modeIndicator.querySelector('div').style.background = 'var(--accent-gold)';
            modeIndicator.querySelector('div').style.boxShadow = '0 0 10px var(--accent-gold)';
            modeIcon.className = 'fa-solid fa-earth-americas';
            modeIcon.style.color = 'var(--accent-gold)';
            modeText.textContent = 'Market Mode';
            modeText.style.color = 'var(--accent-gold)';
            balanceDisplay.style.color = 'var(--accent-purple)';
            balanceDisplay.style.textShadow = '0 0 10px rgba(168, 85, 247, 0.3)';
        } else {
            modeIndicator.className = 'mode-sanctum';
            modeIndicator.style.borderColor = 'var(--surface-700)';
            modeIndicator.style.background = 'rgba(0,0,0,0.2)';
            modeIndicator.querySelector('div').style.background = 'var(--primary-500)';
            modeIndicator.querySelector('div').style.boxShadow = '0 0 10px var(--primary-500)';
            modeIcon.className = 'fa-solid fa-shield-halved';
            modeIcon.style.color = 'var(--primary-400)';
            modeText.textContent = 'Sanctum Mode';
            modeText.style.color = 'var(--primary-400)';
            balanceDisplay.style.color = 'var(--accent-gold)';
            balanceDisplay.style.textShadow = 'none';
        }
    }

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (!item.dataset.target) return;
            setActiveView(item.dataset.target);
        });
    });

    navSubItems.forEach(item => {
        item.addEventListener('click', () => {
            if (!item.dataset.extension) return;
            setActiveView('view-extensions', { extensionFilter: item.dataset.extension });
        });
    });

    window.addEventListener('hashchange', activateViewFromHash);
    activateViewFromHash();

    async function loadSettingsIdentity() {
        const inputDevice = document.getElementById('settingsDeviceName');
        const inputDisplay = document.getElementById('settingsDisplayName');
        const inputAvatar = document.getElementById('settingsAvatarUrl');
        const preview = document.getElementById('settingsAvatarPreview');
        const inputPersona = document.getElementById('settingsPersona');
        const inputRole = document.getElementById('settingsRole');
        const inputEmail = document.getElementById('settingsEmail');
        const inputMessenger = document.getElementById('settingsMessenger');
        const inputPhone = document.getElementById('settingsPhone');
        try {
            const res = await apiFetch(`${API}/api/agents/local`);
            if (res.ok) {
                const data = await res.json();
                const identity = data.identity || {};
                if (inputDevice) inputDevice.value = identity.device_name || '';
                if (inputDisplay) inputDisplay.value = identity.display_name || data.name || '';
                if (inputAvatar) inputAvatar.value = identity.avatar_url || '';
                if (preview) {
                    const url = identity.avatar_url || '';
                    if (url) {
                        preview.src = url;
                        preview.style.display = 'block';
                    } else {
                        preview.style.display = 'none';
                    }
                }
                if (inputPersona) inputPersona.value = identity.persona || '';
                if (inputRole) inputRole.value = identity.role || '';
                if (inputEmail) inputEmail.value = identity.email || '';
                if (inputMessenger) inputMessenger.value = identity.messenger || '';
                if (inputPhone) inputPhone.value = identity.phone || '';
            }
        } catch (_) {}
    }

    function readFileAsDataUrl(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = () => reject(reader.error);
            reader.readAsDataURL(file);
        });
    }

    async function uploadAvatar() {
        const fileInput = document.getElementById('settingsAvatarFile');
        const inputAvatar = document.getElementById('settingsAvatarUrl');
        const preview = document.getElementById('settingsAvatarPreview');
        if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
            showToast('Select an image file first', 'error');
            return null;
        }
        const file = fileInput.files[0];
        if (!file.type.startsWith('image/')) {
            showToast('Avatar must be an image', 'error');
            return null;
        }
        const dataUrl = await readFileAsDataUrl(file);
        const res = await apiFetch(`${API}/api/config/avatar`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ data_url: dataUrl, filename: file.name })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const avatarUrl = data.avatar_url || '';
        if (inputAvatar) inputAvatar.value = avatarUrl;
        if (preview && avatarUrl) {
            preview.src = `${avatarUrl}?ts=${Date.now()}`;
            preview.style.display = 'block';
        }
        fileInput.value = '';
        showToast('Avatar uploaded', 'success');
        return avatarUrl;
    }

    async function submitIdentitySettings() {
        const btn = document.getElementById('settingsIdentitySaveBtn');
        const inputDevice = document.getElementById('settingsDeviceName');
        const inputDisplay = document.getElementById('settingsDisplayName');
        const inputAvatar = document.getElementById('settingsAvatarUrl');
        const inputPersona = document.getElementById('settingsPersona');
        const inputRole = document.getElementById('settingsRole');
        const inputEmail = document.getElementById('settingsEmail');
        const inputMessenger = document.getElementById('settingsMessenger');
        const inputPhone = document.getElementById('settingsPhone');

        const deviceName = inputDevice?.value.trim() || '';
        const displayName = inputDisplay?.value.trim() || '';
        if (!deviceName && !displayName) {
            showToast('Agent name or device name is required', 'error');
            return;
        }
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving';
        }
        try {
            const fileInput = document.getElementById('settingsAvatarFile');
            if (fileInput && fileInput.files && fileInput.files.length > 0) {
                await uploadAvatar();
            }
            const res = await apiFetch(`${API}/api/config/identity`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device_name: deviceName || undefined,
                    display_name: displayName || undefined,
                    avatar_url: inputAvatar?.value.trim() || undefined,
                    persona: inputPersona?.value.trim() || undefined,
                    role: inputRole?.value.trim() || undefined,
                    email: inputEmail?.value.trim() || undefined,
                    messenger: inputMessenger?.value.trim() || undefined,
                    phone: inputPhone?.value.trim() || undefined,
                })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            showToast('Identity saved. Restart required.', 'success');
        } catch (e) {
            showToast(`Failed to save identity: ${e?.message || 'unknown error'}`, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-check"></i> Save';
            }
        }
    }

    const settingsSaveBtn = document.getElementById('settingsIdentitySaveBtn');
    if (settingsSaveBtn) {
        settingsSaveBtn.addEventListener('click', submitIdentitySettings);
    }

    const settingsAvatarUploadBtn = document.getElementById('settingsAvatarUploadBtn');
    if (settingsAvatarUploadBtn) {
        settingsAvatarUploadBtn.addEventListener('click', async () => {
            try {
                await uploadAvatar();
            } catch (e) {
                showToast(`Avatar upload failed: ${e?.message || 'unknown error'}`, 'error');
            }
        });
    }

    async function fetchStatus() {
        try {
            const res = await apiFetch(`${API}/api/status`);
            if (res.ok) {
                const status = await res.json();
                AppState.set('status', status);
                renderEconomy(status);

                // Update Mission Control Infrastructure
                const cpu = Number(status?.cpu_usage  -  0);
                const mem = Number(status?.memory_percent  -  0);
                const uptime = Number(status?.uptime_secs  -  0);
                const mcCpu = document.getElementById('mcCpu');
                const mcRam = document.getElementById('mcRam');
                const mcUptime = document.getElementById('mcUptime');
                if (mcCpu) {
                    mcCpu.textContent = `${cpu.toFixed(0)}%`;
                    mcCpu.style.color = cpu > 80 ? 'var(--accent-red)' : cpu > 50 ? 'var(--accent-gold)' : 'var(--accent-green)';
                }
                if (mcRam) {
                    mcRam.textContent = `${mem.toFixed(0)}%`;
                    mcRam.style.color = mem > 80 ? 'var(--accent-red)' : mem > 50 ? 'var(--accent-gold)' : 'var(--text-primary)';
                }
                if (mcUptime) {
                    mcUptime.textContent = formatDuration(uptime);
                }

                // Update greeting
                const greetingEl = document.getElementById('greeting-text');
                if (greetingEl) {
                    const hour = new Date().getHours();
                    const period = hour < 5 ? 'night' : hour < 12 ? 'morning' : hour < 17 ? 'afternoon' : 'evening';
                    const systemMsg = cpu > 80 ? 'system load is elevated' : 'all systems are running smoothly';
                    greetingEl.innerHTML = `Good <span style="font-weight:700;">${period}</span>, ${systemMsg}`;
                }

                appendSessionLog('Status updated', 'info');
            }
        } catch(e) {
            appendSessionLog('Failed to load status', 'error');
        }

        await refreshAgentsUI();

        // Update Agent Fleet in Mission Control
        const fleetEl = document.getElementById('mcAgentFleet');
        if (fleetEl && cachedAgents.length > 0) {
            const online = cachedAgents.filter(a => normalizeAgentStatus(a.status) === 'online');
            fleetEl.innerHTML = (online.length > 0 ? online : cachedAgents).slice(0, 4).map(a => {
                const isOnline = normalizeAgentStatus(a.status) === 'online';
                return `
                    <div style="flex:1; background:var(--surface-800); border-radius:8px; padding:12px; display:flex; align-items:center; gap:10px; cursor:pointer;" onclick="setActiveView('view-market')">
                        <div class="status-dot ${isOnline ? 'online' : 'offline'}"></div>
                        <div style="flex:1;">
                            <div style="font-size:12px; font-weight:500;">${escapeHtml(a.name)}</div>
                            <div style="font-size:10px; color:var(--text-muted);">${escapeHtml(a.profile || 'Worker')}</div>
                        </div>
                        <i class="fa-solid fa-chevron-right" style="font-size:10px; color:var(--text-muted);"></i>
                    </div>
                `;
            }).join('');
        }

        // Populate Progress Timeline with activities
        try {
            const actRes = await apiFetch(`${API}/api/activities?limit=6`);
            if (actRes.ok) {
                const payload = await actRes.json();
                const entries = Array.isArray(payload) ? payload : (payload.entries || []);
                lastActivityEntries = entries;
                const timelineEl = document.getElementById('mcProgressTimeline');
                if (timelineEl && entries.length > 0) {
                    timelineEl.innerHTML = entries.slice(0, 8).map(a => {
                        const time = new Date(a.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                        const label = activityLabel(a);
                        return `
                            <div style="display:flex; align-items:baseline; gap:10px; font-size:12px;">
                                <span style="font-family:var(--font-mono); color:var(--text-muted); min-width:44px;">${time}</span>
                                <span>${escapeHtml(label)}</span>
                            </div>
                        `;
                    }).join('');
                }
            }
        } catch (_) {}
        
        updateMissionHistoryPanels();
        await fetchActivityStats();
        await fetchMarketStats();
        await fetchTasks();
        await fetchActiveMission();
        await fetchInfraSummary();
        await fetchSettings();
    }

    async function fetchActivityStats() {
        try {
            const res = await apiFetch(`${API}/api/activities/stats`);
            if (!res.ok) return;
            lastActivityStats = await res.json();
            renderMarketStats(lastStatus);
        } catch (_) {}
    }

    async function fetchMarketStats() {
        try {
            const res = await apiFetch(`${API}/api/market/stats`, { cache: 'no-store' });
            if (!res.ok) return;
            lastMarketStats = await res.json();
            renderMarketStats(lastStatus);
        } catch (_) {}
    }

    function updateMissionHistoryPanels() {
        const historyEl = document.getElementById('mcHistory');
        const completionEl = document.getElementById('mcCompletionHistory');

        if (historyEl) {
            if (!lastActivityEntries.length) {
                historyEl.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">No recent activity.</div>';
            } else {
                historyEl.innerHTML = lastActivityEntries.slice(0, 6).map(entry => {
                    const time = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const label = activityLabel(entry);
                    const typeTag = getActivityType(entry).tag;
                    return `
                        <div style="display:flex; align-items:center; gap:12px; padding:10px; border-radius:8px; background:var(--surface-800);">
                            <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); min-width:52px;">${time}</div>
                            <div style="flex:1;">
                                <div style="font-size:12px; font-weight:600;">${escapeHtml(label)}</div>
                                <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase;">${escapeHtml(typeTag)}</div>
                            </div>
                        </div>
                    `;
                }).join('');
            }
        }

        if (completionEl) {
            const doneTasks = (lastTasks || []).filter(t => String(t.status || '').toLowerCase().includes('done'));
            if (doneTasks.length > 0) {
                completionEl.innerHTML = doneTasks.slice(0, 6).map(task => {
                    const time = new Date(task.updated_at || task.created_at || Date.now())
                        .toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    return `
                        <div style="display:flex; align-items:center; gap:12px; padding:10px; border-radius:8px; background:var(--surface-800);">
                            <div class="status-dot online"></div>
                            <div style="flex:1;">
                                <div style="font-size:12px; font-weight:600;">${escapeHtml(task.title || 'Completed task')}</div>
                                <div style="font-size:10px; color:var(--text-muted);">Completed ${time}</div>
                            </div>
                        </div>
                    `;
                }).join('');
            } else if (lastActivityEntries.length > 0) {
                completionEl.innerHTML = lastActivityEntries.slice(0, 6).map(entry => {
                    const time = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                    const label = activityLabel(entry);
                    return `
                        <div style="display:flex; align-items:center; gap:12px; padding:10px; border-radius:8px; background:var(--surface-800);">
                            <div class="status-dot online"></div>
                            <div style="flex:1;">
                                <div style="font-size:12px; font-weight:600;">${escapeHtml(label)}</div>
                                <div style="font-size:10px; color:var(--text-muted);">${time}</div>
                            </div>
                        </div>
                    `;
                }).join('');
            } else {
                completionEl.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">No completions yet.</div>';
            }
        }
    }

    async function fetchSettings() {
        try {
            const res = await apiFetch(`${API}/api/config`);
            if (res.ok) {
                const config = await res.json();
                const agent = config.agent || {};
                
                // Populate Identity Tab
                const fields = {
                    'settingsDisplayName': agent.display_name,
                    'settingsDeviceName': agent.device_name,
                    'settingsAvatarUrl': agent.avatar_url,
                    'settingsPersona': agent.persona,
                    'settingsRole': agent.role,
                    'settingsEmail': agent.email,
                    'settingsMessenger': agent.messenger,
                    'settingsPhone': agent.phone
                };
                
                for (const [id, val] of Object.entries(fields)) {
                    const el = document.getElementById(id);
                    if (el) el.value = val || '';
                }

                if (agent.avatar_url && document.getElementById('settingsAvatarPreview')) {
                    document.getElementById('settingsAvatarPreview').src = agent.avatar_url;
                    document.getElementById('settingsAvatarPreview').style.display = 'block';
                }

                // Populate Security Tab
                const apiKeyEl = document.getElementById('settingsApiKey');
                if (apiKeyEl) {
                    const host = config.webui?.bind || '127.0.0.1';
                    const port = config.webui?.port || agent.listen_port || '';
                    const device = agent.display_name || agent.device_name || 'EdgeClaw';
                    apiKeyEl.textContent = port ? `${device}@${host}:${port}` : device;
                }
            }
        } catch (e) {
            console.error("Failed to fetch settings:", e);
        }
    }

    async function fetchActiveMission() {
        const nameEl = document.getElementById('mcMissionName');
        const pctEl = document.getElementById('mcMissionPct');
        const barEl = document.getElementById('mcMissionBar');
        const etaEl = document.getElementById('mcMissionEta');
        const stepsEl = document.getElementById('mcMissionSteps');

        const normalizePercent = (value) => {
            const num = Number(value);
            if (!Number.isFinite(num)) return 0;
            if (num <= 1) return Math.round(num * 100);
            return Math.min(100, Math.round(num));
        };

        const taskStepsFromList = (tasks) => {
            if (!Array.isArray(tasks) || tasks.length === 0) return [];
            return tasks.slice(0, 3).map((t, idx) => {
                const status = String(t.status || '').toLowerCase();
                const isDone = status.includes('done');
                const isRunning = status.includes('progress') || status.includes('review');
                return {
                    index: idx + 1,
                    name: t.title || `Task ${idx + 1}`,
                    state: isDone ? 'Completed' : (isRunning ? 'Running' : 'Pending'),
                };
            });
        };

        try {
            let mission = null;
            const res = await apiFetch(`${API}/api/v1/mission/active`);
            if (res.ok) {
                mission = await res.json();
            } else {
                const fallback = await apiFetch(`${API}/api/missions`);
                if (fallback.ok) {
                    const list = await fallback.json();
                    mission = (list.missions || [])[0] || null;
                }
            }

            if (!mission) {
                const derivedSteps = taskStepsFromList(lastTasks);
                if (nameEl) nameEl.textContent = lastTasks?.[0]?.title || 'No active mission';
                if (pctEl) pctEl.textContent = derivedSteps.length ? '10%' : '--';
                if (barEl) barEl.style.width = derivedSteps.length ? '10%' : '0%';
                if (etaEl) etaEl.textContent = derivedSteps.length ? 'Approx 5m remaining' : '--';
                if (stepsEl) {
                    stepsEl.innerHTML = derivedSteps.length
                        ? derivedSteps.map(s => `
                            <div style="display:flex; align-items:center; gap:12px; padding:10px 12px; background:var(--surface-800); border-radius:8px; opacity:0.6;">
                                <span style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted); width:20px;">${s.index}</span>
                                <i class="fa-solid fa-file-lines" style="color:var(--text-muted); font-size:12px;"></i>
                                <span style="flex:1; font-size:13px;">${escapeHtml(s.name)}</span>
                                <span class="badge" style="font-size:10px;">Pending</span>
                            </div>
                        `).join('')
                        : '<div style="font-size:12px; color:var(--text-muted);">No active mission.</div>';
                }
                return;
            }

            const pct = normalizePercent(mission.progress ?? mission.progress_pct);
            if (nameEl) nameEl.textContent = mission.name || mission.title || 'Active Mission';
            if (pctEl) pctEl.textContent = `${pct}%`;
            if (barEl) barEl.style.width = `${pct}%`;
            if (etaEl) {
                const eta = mission.eta_sec ?? mission.eta_secs ?? null;
                etaEl.textContent = eta ? `Approx ${Math.ceil(eta / 60)}m remaining` : '--';
            }

            const steps = Array.isArray(mission.steps) && mission.steps.length
                ? mission.steps
                : taskStepsFromList(lastTasks);
            if (stepsEl) {
                if (!steps.length) {
                    stepsEl.innerHTML = '<div style="font-size:12px; color:var(--text-muted);">No steps available.</div>';
                } else {
                    stepsEl.innerHTML = steps.map((s, idx) => {
                        const state = s.state || s.status || '';
                        const isDone = String(state).toLowerCase().includes('complete') || String(state).toLowerCase().includes('done');
                        const isRunning = String(state).toLowerCase().includes('running') || String(state).toLowerCase().includes('progress');
                        const stepIndex = s.index ?? (idx + 1);
                        return `
                            <div style="display:flex; align-items:center; gap:12px; padding:10px 12px; background:var(--surface-800); border-radius:8px; ${isRunning ? 'border-left:3px solid var(--primary-500);' : (isDone ? '' : 'opacity:0.6;')}">
                                <span style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted); width:20px;">${stepIndex}</span>
                                <i class="fa-solid ${isDone ? 'fa-database' : (isRunning ? 'fa-brain' : 'fa-file-lines')}" style="color:${isDone ? 'var(--accent-green)' : (isRunning ? 'var(--primary-400)' : 'var(--text-muted)')}; font-size:12px;"></i>
                                <span style="flex:1; font-size:13px;">${escapeHtml(s.name || s.title || 'Step')}</span>
                                <span class="badge ${isDone ? 'badge-green' : (isRunning ? 'badge-blue' : '')}" style="font-size:10px;">
                                    ${isDone ? '<i class="fa-solid fa-check"></i> Completed' : (isRunning ? '<i class="fa-solid fa-spinner fa-spin" style="font-size:8px;"></i> In Progress' : 'Pending')}
                                </span>
                            </div>
                        `;
                    }).join('');
                }
            }
        } catch (e) {
            console.error("Failed to fetch active mission:", e);
        }
    }

    async function fetchInfraSummary() {
        try {
            const res = await apiFetch(`${API}/api/v1/infra/summary`);
            if (res.ok) {
                const infra = await res.json();
                const mcCpu = document.getElementById('mcCpu');
                const mcRam = document.getElementById('mcRam');
                const mcContainers = document.getElementById('mcContainers');
                const mcUptime = document.getElementById('mcUptime');

                if (mcCpu) {
                    mcCpu.textContent = `${Number(infra.cpu_pct || 0).toFixed(0)}%`;
                    mcCpu.style.color = infra.cpu_pct > 80 ? 'var(--accent-red)' : 'var(--accent-green)';
                }
                if (mcRam) mcRam.textContent = `${Number(infra.ram_pct || 0).toFixed(0)}%`;
                if (mcContainers) mcContainers.textContent = infra.containers ?? '--';
                if (mcUptime) mcUptime.textContent = formatDuration(infra.uptime_sec);
            }
        } catch (e) {
            console.error("Failed to fetch infra summary:", e);
            if (lastStatus) {
                const mcCpu = document.getElementById('mcCpu');
                const mcRam = document.getElementById('mcRam');
                const mcUptime = document.getElementById('mcUptime');
                if (mcCpu) mcCpu.textContent = `${Number(lastStatus.cpu_usage || 0).toFixed(0)}%`;
                if (mcRam) mcRam.textContent = `${Number(lastStatus.memory_percent || 0).toFixed(0)}%`;
                if (mcUptime) mcUptime.textContent = formatDuration(lastStatus.uptime_secs || 0);
            }
        }
    }

    document.getElementById('sidebarDeviceGroups').addEventListener('click', (e) => {
        const item = e.target.closest('.device-item[data-agent-id]');
        if (!item) return;
        selectedAgentId = item.dataset.agentId;
        selectedAgentName = item.dataset.agentName || selectedAgentId;
        highlightSidebarSelection();
        updateContextPanel(selectedAgentId, 'Device');
        fetchTasks();
        showToast(`Connected to ${selectedAgentName}`, 'success');
    });

    function contextFromTask(task) {
        const title = task?.title || 'No active context';
        const status = String(task?.status || 'todo').toLowerCase();
        const priority = String(task?.priority || 'normal').toLowerCase();
        const progress = status.includes('done') ? 100 : status.includes('progress') ? 60 : 10;

        const badges = [];
        if (priority.includes('high') || priority.includes('urgent')) {
            badges.push({ text: 'Risk: L2', className: 'badge-gold' });
        } else if (priority.includes('low')) {
            badges.push({ text: 'Risk: L0', className: 'badge-green' });
        } else {
            badges.push({ text: 'Risk: L1', className: 'badge-blue' });
        }
        if (task?.assignee) {
            badges.push({ text: `Assignee: ${task.assignee}`, className: 'badge' });
        }
        if (task?.status) {
            badges.push({ text: String(task.status), className: 'badge' });
        }

        return { title, progress, badges };
    }

    function contextFromTasks(tasks, agentId) {
        if (!Array.isArray(tasks) || tasks.length === 0) {
            return { title: 'No active context', progress: 0, badges: [] };
        }
        const agentTasks = agentId ? tasks.filter(t => String(t.assignee || '') === String(agentId)) : tasks;
        const pool = agentTasks.length ? agentTasks : tasks;
        const inProgress = pool.find(t => String(t.status || '').toLowerCase().includes('progress'));
        const todo = pool.find(t => String(t.status || '').toLowerCase().includes('todo') || String(t.status || '').toLowerCase().includes('backlog'));
        const done = pool.find(t => String(t.status || '').toLowerCase().includes('done'));
        return contextFromTask(inProgress || todo || done || pool[0]);
    }

    function renderContextBlock(context) {
        const titleEl = document.getElementById('context-title');
        const progressEl = document.getElementById('context-progress');
        const badgesEl = document.getElementById('context-badges');

        if (titleEl) setTranslatedText(titleEl, context.title || 'No active context');
        if (progressEl) progressEl.style.width = `${Math.max(0, Math.min(100, context.progress || 0))}%`;
        if (badgesEl) {
            badgesEl.innerHTML = '';
            (context.badges || []).forEach(badge => {
                const span = document.createElement('span');
                span.className = `badge ${badge.className || ''}`.trim();
                setTranslatedText(span, badge.text || '');
                badgesEl.appendChild(span);
            });
        }
    }

    // Handle Context Panel Update
    async function updateContextPanel(id, type) {
        const panel = document.getElementById('context-panel');
        panel.style.display = 'flex';
        panel.style.width = '320px';
        
        let name = id;
        let repScore = null;
        let profile = "Unknown";
        let status = "online";
        let address = null;
        let port = null;
        let avatarUrl = '';
        let persona = '';
        let role = '';
        let email = '';
        let messenger = '';
        let phone = '';
        let systemInfo = null;
        let recentTasks = null;
        
        let contextPayload = contextFromTasks(lastTasks, selectedAgentId);

        if (type === 'Agent' || type === 'Device') {
            try {
                const res = await apiFetch(`${API}/api/agents/${id}`);
                if (res.ok) {
                    const data = await res.json();
            const showOffline = document.getElementById('marketShowOffline')?.checked;
                    const identity = data.identity || {};
                    name = identity.display_name || data.name || id;
                    repScore = typeof data.reputation_score === 'number' ? data.reputation_score : null;
                    profile = data.profile || 'all';
                    status = data.status || 'offline';
                    address = data.address || null;
                    port = data.port || null;
                    avatarUrl = identity.avatar_url || '';
                    persona = identity.persona || '';
                    role = identity.role || '';
                    email = identity.email || '';
                    messenger = identity.messenger || '';
                    phone = identity.phone || '';
                    systemInfo = data.system || null;
                    recentTasks = Array.isArray(data.recent_tasks) ? data.recent_tasks : null;
                    if (recentTasks && recentTasks.length) {
                        contextPayload = contextFromTasks(recentTasks, id);
                    }
                }
            } catch(e) {
                appendSessionLog('Context panel fallback used', 'warn');
            }
        } else if (type === 'Task') {
            const task = (lastTasks || []).find(t => String(t.id) === String(id) || String(t.title) === String(id));
            if (task) {
                name = task.title || id;
                status = task.status || 'active';
                contextPayload = contextFromTask(task);
            } else {
                contextPayload = { title: String(id || 'Task'), progress: 0, badges: [] };
            }
        }
        
        const headerName = panel.querySelector('.context-header div');
        headerName.innerHTML = `<div class="status-dot ${status === 'online' ? 'online' : 'offline'}"></div> ${escapeHtml(name)}`;
        
        const scoreText = repScore == null ? '--' : Number(repScore).toFixed(1);
        const idBlock = panel.querySelector('.info-block:nth-child(1)');
        const details = [];
        if (type !== 'Task' && profile) details.push(`Profile: ${profile}`);
        if (type !== 'Task' && address) details.push(`Addr: ${address}${port ? `:${port}` : ''}`);
        if (type !== 'Task' && systemInfo?.platform) details.push(`Host: ${systemInfo.platform}`);
        if (type === 'Task') {
            const task = (lastTasks || []).find(t => String(t.id) === String(id) || String(t.title) === String(id));
            if (task?.assignee) details.push(`Assignee: ${task.assignee}`);
            if (task?.priority) details.push(`Priority: ${task.priority}`);
        }
        if (type !== 'Task') {
            if (role) details.push(`Role: ${role}`);
            if (email) details.push(`Email: ${email}`);
            if (messenger) details.push(`Messenger: ${messenger}`);
            if (phone) details.push(`Mobile: ${phone}`);
        }
        const detailsHtml = details.length
            ? `<div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">${details.map(escapeHtml).join('  - ')}</div>`
            : '';

        idBlock.innerHTML = `
            <h4>${type} Identity</h4>
            <div class="nft-card">
                <div style="font-size:14px; font-weight:600; margin-bottom:12px; display:flex; justify-content:space-between;">
                    <span>${type === 'Task' ? 'Task ID' : 'Passport NFT'}</span>
                    <i class="fa-brands fa-ethereum" style="color:var(--accent-purple)"></i>
                </div>
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                    <div style="width:36px; height:36px; border-radius:10px; background:var(--surface-800); border:1px solid var(--surface-700); display:flex; align-items:center; justify-content:center; overflow:hidden;">
                        ${avatarUrl ? `<img src="${escapeHtml(avatarUrl)}" alt="avatar" style="width:100%; height:100%; object-fit:cover;">` : '<i class="fa-solid fa-user" style="color:var(--text-muted)"></i>'}
                    </div>
                    <div style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted);">${escapeHtml(id)}</div>
                </div>
                ${persona ? `<div style="font-size:11px; color:var(--text-secondary); margin-bottom:8px;">${escapeHtml(persona)}</div>` : ''}
                ${detailsHtml}
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="badge ${status === 'online' ? 'badge-green' : 'badge-red'}">${status.toUpperCase()}</span>
                    <span style="font-weight:600; color:var(--accent-gold)"><i class="fa-solid fa-star"></i> ${scoreText}</span>
                </div>
            </div>
        `;

        renderContextBlock(contextPayload);
        
        const logContainer = panel.querySelector('.info-block:last-child div');
        const newLog = document.createElement('div');
        newLog.className = 'log-entry';
        const now = new Date();
        newLog.innerHTML = `<span class="log-time">${now.getHours()}:${now.getMinutes().toString().padStart(2,'0')}</span> <span>Selected ${escapeHtml(type)}: ${escapeHtml(name)}</span>`;
        logContainer.prepend(newLog);
        while (logContainer.children.length > 10) {
            logContainer.removeChild(logContainer.lastChild);
        }
    }

    // Native HTML5 Drag and Drop for Kanban Board (P4-1-3)
    function allowDrop(ev) {
        ev.preventDefault();
        ev.currentTarget.style.background = 'rgba(99, 102, 241, 0.1)';
        ev.currentTarget.style.borderStyle = 'dashed';
        ev.currentTarget.style.borderColor = 'var(--primary-500)';
    }

    function drag(ev) {
        ev.dataTransfer.setData("taskId", ev.target.dataset.id || ev.target.id);
        ev.dataTransfer.setData("elementId", ev.target.id);
        setTimeout(() => ev.target.classList.add('dragging'), 0);
    }

    async function drop(ev, colId) {
        ev.preventDefault();
        
        const col = ev.currentTarget;
        col.style.background = 'rgba(28, 28, 40, 0.4)';
        col.style.borderStyle = 'solid';
        col.style.borderColor = 'var(--surface-700)';
        
        const taskId = ev.dataTransfer.getData("taskId");
        const elementId = ev.dataTransfer.getData("elementId");
        const draggedElement = document.getElementById(elementId);
        
        if(draggedElement) {
            draggedElement.classList.remove('dragging');
            const cardsContainer = col.querySelector('.kanban-cards');
            cardsContainer.appendChild(draggedElement);
            
            // Sync with backend
            try {
                const res = await apiFetch(`${API}/api/tasks/${taskId}/move`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ status: colId })
                });
                if (res.ok) {
                    showToast(`Task moved to ${colId}`, 'success');
                }
            } catch(e) {
                showToast("Failed to sync task move", "error");
            }
        }
    }

    // Reset column drag styling on leave
    document.querySelectorAll('.kanban-col').forEach(col => {
        col.addEventListener('dragleave', (e) => {
            // Only reset if we actually leave the column (not just hovering over children)
            if (e.target === col) {
                col.style.background = 'rgba(28, 28, 40, 0.4)';
                col.style.borderStyle = 'solid';
                col.style.borderColor = 'var(--surface-700)';
            }
        });
    });

    // Close Context Panel
    document.querySelector('.context-header .fa-xmark').addEventListener('click', () => {
        const panel = document.getElementById('context-panel');
        panel.style.width = '0px';
        setTimeout(() => panel.style.display = 'none', 300);
    });

    function showRentPolicyModal() {
        const modal = document.getElementById('rentPolicyModal');
        if (modal) modal.style.display = 'flex';
        loadRentPolicy();
    }

    function hideRentPolicyModal() {
        const modal = document.getElementById('rentPolicyModal');
        if (modal) modal.style.display = 'none';
    }

    async function loadRentPolicy() {
        try {
            const res = await apiFetch(`${API}/api/rent-policies`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            document.getElementById('rentBaseRate').value = data.base_rate ?? 0;
            document.getElementById('rentMaxActive').value = data.max_active ?? 0;
            document.getElementById('rentMinRep').value = data.min_reputation ?? 0;
            document.getElementById('rentAutoApprove').checked = !!data.auto_approve;
        } catch (e) {
            showToast(`Failed to load rent policy: ${e?.message || 'unknown error'}`, 'error');
        }
    }

    async function submitRentPolicy() {
        const btn = document.getElementById('rentPolicySubmitBtn');
        if (btn) {
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving';
        }
        try {
            const payload = {
                base_rate: parseFloat(document.getElementById('rentBaseRate').value || '0'),
                max_active: parseInt(document.getElementById('rentMaxActive').value || '0', 10),
                min_reputation: parseFloat(document.getElementById('rentMinRep').value || '0'),
                auto_approve: document.getElementById('rentAutoApprove').checked,
            };
            const res = await apiFetch(`${API}/api/rent-policies`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            showToast('Rent policy saved', 'success');
            hideRentPolicyModal();
        } catch (e) {
            showToast(`Save failed: ${e?.message || 'unknown error'}`, 'error');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-check"></i> Save Policy';
            }
        }
    }

    const manageRentBtn = document.getElementById('manageRentBtn');
    if (manageRentBtn) {
        manageRentBtn.addEventListener('click', showRentPolicyModal);
    }

    // Marketplace Interactions (event delegation for dynamic cards)
    const marketGrid = document.getElementById('marketGrid');
    if (marketGrid) {
        marketGrid.addEventListener('click', (e) => {
            const card = e.target.closest('.agent-card');
            if (!card) return;

            const agentId = card.dataset.agentId || 'unknown';
            const agentName = card.dataset.agentName || agentId;

            if (e.target.closest('.inspect-agent-btn')) {
                updateContextPanel(agentId, 'Agent');
                showToast(`Viewing ${agentName} profile`, 'info');
                return;
            }

            if (e.target.closest('.hire-agent-btn')) {
                hireAgent(agentId, agentName);
            }
        });
    }

    async function hireAgent(agentId, agentName) {
        showToast(`Hiring request sent to ${agentName}`, 'info');
        try {
            const res = await apiFetch(`${API}/api/tasks`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title: `Hire agent: ${agentName}`,
                    description: `Marketplace hire request for ${agentName} (${agentId}).`,
                    priority: 'Medium',
                    assignee: selectedAgentId || 'local',
                    tags: ['marketplace', 'hire']
                })
            });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            showToast(`${agentName} assignment queued`, 'success');
            fetchTasks();
        } catch (e) {
            showToast(`Hire failed: ${e?.message || 'unknown error'}`, 'error');
        }
    }

    // Memory Tier Switching
    document.querySelectorAll('.tier-item').forEach(tier => {
        tier.addEventListener('click', () => {
            document.querySelectorAll('.tier-item').forEach(t => t.classList.remove('active'));
            tier.classList.add('active');
            const tierKey = tier.dataset.tier || 'core';

            const titleEl = document.getElementById('memoryContentTitle');
            if (titleEl) titleEl.textContent = memoryTitleForTier(tierKey);
            fetchMemory();
            showToast(`Loading: ${memoryTitleForTier(tierKey)}`, 'info');
        });
    });

    async function fetchTasks() {
        try {
            const query = selectedAgentId ? `?assignee=${encodeURIComponent(selectedAgentId)}` : '';
            const res = await apiFetch(`${API}/api/tasks${query}`);
            if (!res.ok) throw new Error(`tasks ${res.status}`);
            const tasks = await res.json();
            
            document.querySelectorAll('#col-todo .kanban-cards, #col-progress .kanban-cards, #col-done .kanban-cards')
                .forEach(c => c.innerHTML = '');
            
            tasks.forEach(task => {
                const col = document.getElementById(`col-${taskColumnId(task.status)}`) || document.getElementById('col-todo');
                const container = col.querySelector('.kanban-cards');
                const card = document.createElement('div');
                card.className = 'task-card';
                card.draggable = true;
                card.id = `task-${task.id}`;
                card.dataset.id = task.id;                const titleText = task.title || '';
                const priorityText = task.priority || 'Normal';
                const assigneeText = task.assignee || '-';
                const createdDate = new Date(task.created_at).toLocaleDateString();
                const priorityNorm = String(priorityText).toLowerCase();
                const isHigh = priorityNorm.includes('high') || priorityNorm.includes('urgent') || priorityNorm.includes('\uB192');
                card.innerHTML = `
                    <div class="task-title"></div>
                    <span class="badge ${isHigh ? 'badge-red' : 'badge-blue'}">Prio: <span class="task-priority"></span></span>
                    <div class="task-meta">
                        <span>Assignee: <span class="task-assignee"></span></span>
                        <span>${createdDate}</span>
                    </div>
                `;
                const titleEl = card.querySelector('.task-title');
                const prioEl = card.querySelector('.task-priority');
                const assigneeEl = card.querySelector('.task-assignee');
                setTranslatedText(titleEl, titleText);
                setTranslatedText(prioEl, priorityText);
                setTranslatedText(assigneeEl, assigneeText);
                card.ondragstart = drag;
                card.ondblclick = () => quickAssignTask(task.id);
                container.appendChild(card);
            });

            const todoCount = document.querySelectorAll('#col-todo .kanban-cards .task-card').length;
            const progCount = document.querySelectorAll('#col-progress .kanban-cards .task-card').length;
            const doneCount = document.querySelectorAll('#col-done .kanban-cards .task-card').length;
            document.querySelector('#col-todo .kanban-header .badge').textContent = todoCount;
            document.querySelector('#col-progress .kanban-header .badge').textContent = progCount;
            document.querySelector('#col-done .kanban-header .badge').textContent = doneCount;

            renderTaskOverview(tasks);
            updateMissionHistoryPanels();
            appendSessionLog('Tasks synced', 'info');
        } catch(e) {
            showToast("Failed to load tasks", "error");
            appendSessionLog('Task fetch failed', 'error');
        }
    }

    async function quickAssignTask(taskId) {
        const localAgents = cachedAgents.filter(agent => String(agent.source || '').toLowerCase() === 'local');
        if (localAgents.length === 0) {
            showToast('No local agents available for assignment', 'error');
            return;
        }

        const target = prompt(
            `Assign task to agent ID:\n${localAgents.map(a => `- ${a.id} (${a.name})`).join('\n')}`,
            selectedAgentId || localAgents[0].id
        );
        if (!target) return;

        try {
            const res = await apiFetch(`${API}/api/tasks/${taskId}/assign`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ assignee: target.trim() }),
            });
            if (res.ok) {
                showToast(`Task assigned to ${target.trim()}`, 'success');
                fetchTasks();
            } else {
                showToast('Failed to assign task', 'error');
            }
        } catch (e) {
            showToast('Failed to assign task', 'error');
        }
    }

    async function fetchMemory() {
        try {
            const res = await apiFetch(`${API}/api/memory`);
            if (!res.ok) throw new Error(`memory ${res.status}`);
            const memory = await res.json();
            lastMemory = memory;
            renderMemoryOverview(memory);
            renderMemoryTiers(memory);
            renderMemoryGraph(memory);
            renderMemoryViewerFeed(memory);
            renderMemoryPopularNodes(memory);
            renderMemoryStorage(memory);

            const activeTier = getActiveMemoryTier();
            const contentArea = document.getElementById('memoryEntry');
            if (!contentArea) return;
            contentArea.innerHTML = '';

            if (activeTier === 'core') {
                const soulLabel = document.createElement('div');
                soulLabel.style.color = 'var(--primary-400)';
                soulLabel.style.marginBottom = '10px';
                soulLabel.textContent = '[SOUL Definition]';

                const soulContent = document.createElement('div');
                soulContent.style.marginBottom = '16px';
                setTranslatedText(soulContent, `"${memory.core?.soul?.content || ''}"`);

                const rulesLabel = document.createElement('div');
                rulesLabel.style.color = 'var(--accent-gold)';
                rulesLabel.style.marginBottom = '10px';
                rulesLabel.textContent = '[Absolute Rules]';

                const rulesList = document.createElement('ul');
                rulesList.style.paddingLeft = '16px';
                rulesList.style.margin = '0';

                const rules = memory.core?.absolute_rules || [];
                if (rules.length === 0) {
                    const empty = document.createElement('div');
                    empty.style.color = 'var(--text-muted)';
                    empty.textContent = 'No rules defined yet.';
                    contentArea.append(soulLabel, soulContent, rulesLabel, empty);
                } else {
                    rules.forEach(rule => {
                        const li = document.createElement('li');
                        li.style.marginBottom = '6px';
                        setTranslatedText(li, rule);
                        rulesList.appendChild(li);
                    });
                    contentArea.append(soulLabel, soulContent, rulesLabel, rulesList);
                }
            } else if (activeTier === 'lessons') {
                const lessons = memory.lessons?.lessons || [];
                if (lessons.length === 0) {
                    const empty = document.createElement('div');
                    empty.style.color = 'var(--text-muted)';
                    empty.textContent = 'No lessons distilled yet.';
                    contentArea.appendChild(empty);
                } else {
                    lessons.forEach(lesson => {
                        const item = document.createElement('div');
                        item.style.marginBottom = '12px';

                        const title = document.createElement('div');
                        title.style.fontWeight = '600';
                        setTranslatedText(title, lesson.pattern || '');

                        const meta = document.createElement('div');
                        meta.style.fontSize = '11px';
                        meta.style.color = 'var(--text-muted)';
                        meta.textContent = `Effectiveness: ${lesson.effectiveness ?? '-'}`;

                        item.appendChild(title);
                        item.appendChild(meta);
                        contentArea.appendChild(item);
                    });
                }
            } else {
                const tierKey = activeTier;
                const memories = memory.tiers?.[tierKey] || [];
                if (memories.length === 0) {
                    const empty = document.createElement('div');
                    empty.style.color = 'var(--text-muted)';
                    empty.textContent = 'No memories in this tier.';
                    contentArea.appendChild(empty);
                } else {
                    memories.forEach(m => {
                        const row = document.createElement('div');
                        row.style.padding = '10px';
                        row.style.borderBottom = '1px solid var(--surface-700)';

                        const content = document.createElement('div');
                        setTranslatedText(content, m.content || '');

                        const meta = document.createElement('div');
                        meta.style.fontSize = '11px';
                        meta.style.color = 'var(--text-muted)';
                        meta.textContent = new Date(m.created_at).toLocaleString();

                        row.appendChild(content);
                        row.appendChild(meta);
                        contentArea.appendChild(row);
                    });
                }
            }

            appendSessionLog('Memory synced', 'info');
        } catch(e) {
            showToast("Failed to load memory", "error");
            appendSessionLog('Memory fetch failed', 'error');
        }
    }

    function showMemoryEditModal(mode) {
        const modal = document.getElementById('memoryEditModal');
        if (!modal) return;
        const tierValue = document.getElementById('memoryEditTierValue');
        const coreSection = document.getElementById('memoryEditCore');
        const tierSection = document.getElementById('memoryEditTier');
        const lessonSection = document.getElementById('memoryEditLesson');
        const subtitle = document.getElementById('memoryEditSubtitle');

        const activeTier = getActiveMemoryTier();
        const selectedMode = mode || (activeTier === 'core' ? 'core' : activeTier === 'lessons' ? 'lesson' : 'tier');

        if (tierValue) tierValue.value = selectedMode;
        if (coreSection) coreSection.style.display = selectedMode === 'core' ? 'block' : 'none';
        if (tierSection) tierSection.style.display = selectedMode === 'tier' ? 'block' : 'none';
        if (lessonSection) lessonSection.style.display = selectedMode === 'lesson' ? 'block' : 'none';
        if (subtitle) subtitle.textContent = selectedMode === 'core'
            ? 'Update SOUL definition and rules.'
            : selectedMode === 'lesson'
                ? 'Publish a new lesson pattern.'
                : 'Add a new memory entry.';

        if (selectedMode === 'core' && lastMemory) {
            const soulInput = document.getElementById('memorySoulInput');
            const rulesInput = document.getElementById('memoryRulesInput');
            if (soulInput) soulInput.value = lastMemory.core?.soul?.content || '';
            if (rulesInput) rulesInput.value = (lastMemory.core?.absolute_rules || []).join('\n');
        }

        if (selectedMode === 'tier') {
            const tierSelect = document.getElementById('memoryTierSelect');
            const contentInput = document.getElementById('memoryTierContentInput');
            if (tierSelect) tierSelect.value = ['m30', 'm90', 'm365'].includes(activeTier) ? activeTier : 'm30';
            if (contentInput) contentInput.value = '';
        }

        if (selectedMode === 'lesson') {
            const patternInput = document.getElementById('lessonPatternInput');
            const effectInput = document.getElementById('lessonEffectInput');
            if (patternInput) patternInput.value = '';
            if (effectInput && !effectInput.value) effectInput.value = '0.7';
        }

        modal.style.display = 'flex';
    }

    function hideMemoryEditModal() {
        const modal = document.getElementById('memoryEditModal');
        if (modal) modal.style.display = 'none';
    }

    async function submitMemoryEdit() {
        const mode = document.getElementById('memoryEditTierValue')?.value || 'core';
        const submitBtn = document.getElementById('memoryEditSubmitBtn');
        const originalBtn = submitBtn?.innerHTML || '';

        try {
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
            }

            if (mode === 'core') {
                const soul = document.getElementById('memorySoulInput')?.value?.trim() || '';
                const rulesRaw = document.getElementById('memoryRulesInput')?.value || '';
                const rules = rulesRaw.split('\n').map(r => r.trim()).filter(Boolean);

                const res = await apiFetch(`${API}/api/memory/core`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ soul, rules }),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                showToast('Core memory updated', 'success');
            } else if (mode === 'lesson') {
                const pattern = document.getElementById('lessonPatternInput')?.value?.trim() || '';
                const effectiveness = parseFloat(document.getElementById('lessonEffectInput')?.value || '0.7');
                if (!pattern) {
                    showToast('Lesson pattern is required', 'error');
                    return;
                }
                const res = await apiFetch(`${API}/api/memory/lessons`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ pattern, effectiveness }),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                showToast('Lesson published', 'success');
            } else {
                const tier = document.getElementById('memoryTierSelect')?.value || 'm30';
                const content = document.getElementById('memoryTierContentInput')?.value?.trim() || '';
                if (!content) {
                    showToast('Memory content is required', 'error');
                    return;
                }
                const res = await apiFetch(`${API}/api/memory/tier`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tier, content, importance: 1 }),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                showToast('Memory entry added', 'success');
            }

            hideMemoryEditModal();
            fetchMemory();
        } catch (e) {
            showToast(`Failed to update memory: ${e?.message || 'unknown error'}`, 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtn;
            }
        }
    }

    function showMemoryHistoryModal(title, subtitle) {
        const modal = document.getElementById('memoryHistoryModal');
        const titleEl = document.getElementById('memoryHistoryTitle');
        const subtitleEl = document.getElementById('memoryHistorySubtitle');
        if (titleEl) titleEl.textContent = title || 'Memory History';
        if (subtitleEl) subtitleEl.textContent = subtitle || 'Memory timeline entries.';
        if (modal) modal.style.display = 'flex';
    }

    function hideMemoryHistoryModal() {
        const modal = document.getElementById('memoryHistoryModal');
        if (modal) modal.style.display = 'none';
    }

    function formatMemoryAction(custom) {
        const action = custom?.data?.action;
        if (action === 'core_update') return 'Core Memory Updated';
        if (action === 'tier_add') return 'Memory Added';
        if (action === 'lesson_add') return 'Lesson Published';
        return 'Memory Update';
    }

    function renderMemoryTimeline(list, entries) {
        if (!entries.length) {
            list.innerHTML = '<div style="color:var(--text-muted)">No memory activity yet.</div>';
            return;
        }

        const groups = new Map();
        entries.forEach(entry => {
            const date = new Date(entry.timestamp);
            const dateKey = date.toISOString().slice(0, 10);
            if (!groups.has(dateKey)) groups.set(dateKey, []);
            groups.get(dateKey).push(entry);
        });

        const orderedDates = Array.from(groups.keys()).sort((a, b) => {
            return new Date(b).getTime() - new Date(a).getTime();
        });

        list.innerHTML = '';
        orderedDates.forEach(dateKey => {
            const dateLabel = document.createElement('div');
            dateLabel.className = 'memory-history-date';
            dateLabel.textContent = new Date(dateKey).toLocaleDateString();
            list.appendChild(dateLabel);

            const dayEntries = groups.get(dateKey)
                .slice()
                .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

            dayEntries.forEach(entry => {
                const item = document.createElement('div');
                item.className = 'memory-history-item';

                const custom = getCustomActivity(entry);
                const action = formatMemoryAction(custom);
                const time = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                const header = document.createElement('h4');
                header.innerHTML = `<span>${escapeHtml(action)}</span><span style="color:var(--text-muted); font-weight:500;">${time}</span>`;

                const meta = document.createElement('div');
                meta.className = 'memory-history-meta';
                const tier = custom?.data?.tier ? custom.data.tier.toUpperCase() : null;
                meta.textContent = tier ? `Tier: ${tier}` : 'Memory';

                const body = document.createElement('p');
                setTranslatedText(body, entry.content || '');

                item.appendChild(header);
                item.appendChild(meta);
                item.appendChild(body);
                list.appendChild(item);
            });
        });
    }

    async function loadMemoryHistory(mode, query) {
        const list = document.getElementById('memoryHistoryList');
        if (!list) return;
        list.innerHTML = '<div style="color:var(--text-muted)">Loading...</div>';

        try {
            let entries = [];
            if (mode === 'search') {
                const res = await apiFetch(`${API}/api/activities/search`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query, limit: 20 }),
                });
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                entries = data.entries || [];
            } else if (mode === 'memory') {
                const res = await apiFetch(`${API}/api/activities?limit=200&type=custom`);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                const rawEntries = data.entries || [];
                entries = rawEntries.filter(entry => {
                    const custom = getCustomActivity(entry);
                    return custom && String(custom.category || '').toLowerCase() === 'memory';
                });
                renderMemoryTimeline(list, entries);
                return;
            } else {
                let url = `${API}/api/activities?limit=20`;
                if (mode === 'distillation') url += '&type=custom';
                if (mode === 'git') url += '&type=file_edit';
                const res = await apiFetch(url);
                if (!res.ok) throw new Error(`HTTP ${res.status}`);
                const data = await res.json();
                entries = data.entries || [];
            }

            if (entries.length === 0) {
                list.innerHTML = '<div style="color:var(--text-muted)">No entries found.</div>';
                return;
            }

            list.innerHTML = '';
            entries.forEach(entry => {
                const item = document.createElement('div');
                item.className = 'memory-history-item';

                const typeKey = getActivityType(entry).tag;
                const header = document.createElement('h4');
                header.textContent = `${typeKey}  - ${new Date(entry.timestamp).toLocaleString()}`;

                const body = document.createElement('p');
                setTranslatedText(body, entry.content || '');

                item.appendChild(header);
                item.appendChild(body);
                list.appendChild(item);
            });
        } catch (e) {
            list.innerHTML = `<div style="color:var(--risk-l3)">Failed to load entries (${e?.message || 'unknown error'}).</div>`;
        }
    }
    // Task Interactions
    document.addEventListener('click', (e) => {
        const taskCard = e.target.closest('.task-card');
        if (taskCard) {
            const title = taskCard.querySelector('.task-title')?.textContent || 'Task';
            const taskId = taskCard.dataset.id || title;
            updateContextPanel(taskId, 'Task');
            showToast(`Inspecting Task: ${title}`, 'info');
        }
    });

    // Search Bar Simulation
    const searchInputs = document.querySelectorAll('.search-bar input');
    searchInputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const query = input.value.trim();
                if (query) {
                    showToast(`Searching for: "${query}"...`, 'info');
                    // In a real app, this would filter results or call an API
                }
            }
        });
    });

    // Agent Management
    function showAddAgentModal() {
        document.getElementById('addAgentModal').style.display = 'flex';
    }

    function hideAddAgentModal() {
        document.getElementById('addAgentModal').style.display = 'none';
        document.getElementById('newAgentName').value = '';
    }

    async function submitAddAgent() {
        const name = document.getElementById('newAgentName').value.trim();
        const addr = document.getElementById('newAgentAddr').value.trim();
        const port = parseInt(document.getElementById('newAgentPort').value);

        if (!name || !addr) {
            showToast("Please fill in name and address", "error");
            return;
        }

        try {
            const res = await apiFetch(`${API}/api/agents`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    id: name.toLowerCase().replace(/\s+/g, '-'),
                    name: name,
                    profile: "Worker",
                    address: addr,
                    port: port,
                    status: "offline",
                    capabilities: [],
                    version: "2.0.0",
                    last_heartbeat: new Date().toISOString(),
                    registered_at: new Date().toISOString()
                })
            });

            if (res.ok) {
                showToast(`Agent "${name}" registered`, "success");
                hideAddAgentModal();
                refreshAgentsUI();
                fetchMarketplaceAgents();
            }
        } catch(e) {
            showToast("Failed to register agent", "error");
        }
    }

    async function discoverAgents() {
        const btn = document.getElementById('discoverBtn');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
        btn.disabled = true;

        try {
            const res = await apiFetch(`${API}/api/agents/discover`, { method: 'POST' });
            if (res.ok) {
                const found = await res.json();
                showToast(`Scan complete. Found ${found.length} agents.`, "success");
                refreshAgentsUI();
                fetchMarketplaceAgents();
            }
        } catch(e) {
            showToast("Discovery failed", "error");
        } finally {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    }

    //     Phase 6.9+6.10: Agent Deploy, Install, Inspect                      
    let deployTargetAgentId = null;

    async function inspectAgentModal(agentId) {
        const modal = document.getElementById('agentInspectModal');
        const body  = document.getElementById('inspectAgentBody');
        const title = document.getElementById('inspectAgentTitle');
        if (!modal || !body) return;
        if (title) title.textContent = agentId;
        body.innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-muted);"><i class="fa-solid fa-spinner fa-spin"></i> Loading...</div>';
        modal.classList.add('open');

        try {
            const res = await apiFetch(`${API}/api/agents`);
            if (!res.ok) throw new Error('failed');
            const data = await res.json();
            const list = extractAgentList(data);
            const agent = list.find(a => String(a.id) === agentId) || list[0];
            if (!agent) { body.innerHTML = '<div style="color:var(--text-muted);">Agent not found</div>'; return; }

            body.innerHTML = `
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px;">
                    <div class="ext-modal-field"><label>ID</label><div style="font-size:12px; color:var(--text-primary); font-family:var(--font-mono);">${escapeHtml(agent.id || '-')}</div></div>
                    <div class="ext-modal-field"><label>Name</label><div style="font-size:12px; color:var(--text-primary);">${escapeHtml(agent.name || '-')}</div></div>
                    <div class="ext-modal-field"><label>Address</label><div style="font-size:12px; color:var(--text-primary);">${escapeHtml(agent.address || '127.0.0.1')}:${agent.port || '-'}</div></div>
                    <div class="ext-modal-field"><label>Status</label><div style="font-size:12px; color:${agent.status === 'online' ? 'var(--accent-green)' : 'var(--text-muted)'};">${escapeHtml(agent.status || 'unknown')}</div></div>
                    <div class="ext-modal-field"><label>Profile</label><div style="font-size:12px;">${escapeHtml(agent.profile || 'Worker')}</div></div>
                    <div class="ext-modal-field"><label>Source</label><div style="font-size:12px;">${escapeHtml(agent.source || 'remote')}</div></div>
                </div>
                <div class="ext-modal-field" style="margin-top:8px;">
                    <label>Capabilities</label>
                    <div style="display:flex; gap:6px; flex-wrap:wrap; margin-top:4px;">
                        ${(normalizeCapabilities(agent.capabilities)).map(c => `<span class="badge" style="background:var(--surface-700);">${escapeHtml(c)}</span>`).join('')}
                    </div>
                </div>
            `;
        } catch(e) {
            body.innerHTML = '<div style="color:var(--accent-red);">Failed to load agent details</div>';
        }
    }

    function deployAgent(agentId, agentName) {
        deployTargetAgentId = agentId;
        const title = document.getElementById('deployAgentTitle');
        if (title) title.textContent = agentName || agentId;
        document.getElementById('agentDeployModal')?.classList.add('open');
    }

    async function confirmDeploy() {
        if (!deployTargetAgentId) return;
        const target    = document.getElementById('deployTarget')?.value || 'local';
        const role      = document.getElementById('deployRole')?.value || 'worker';
        const autoStart = document.getElementById('deployAutoStart')?.value === 'yes';
        const notes     = document.getElementById('deployNotes')?.value?.trim() || '';

        showToast(`Deploying ${deployTargetAgentId} to ${target} as ${role}...`, 'info');
        closeExtModal('agentDeployModal');

        // POST deploy request
        try {
            const res = await apiFetch(`${API}/api/agents/deploy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    agent_id: deployTargetAgentId,
                    target, role, auto_start: autoStart, notes
                })
            });
            if (res.ok) {
                showToast(`Agent ${deployTargetAgentId} deployed to ${target}`, 'success');
                fetchMarketplaceAgents();
            } else {
                showToast('Deploy failed  - check agent connectivity', 'error');
            }
        } catch(e) {
            showToast('Deploy request failed', 'error');
        }
    }

    async function installAgent(agentId, agentName) {
        if (!confirm(`Install agent "${agentName}" from marketplace?`)) return;
        showToast(`Installing ${agentName}...`, 'info');
        try {
            const res = await apiFetch(`${API}/api/agents/install`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ agent_id: agentId, name: agentName })
            });
            if (res.ok) {
                showToast(`${agentName} installed successfully`, 'success');
                fetchMarketplaceAgents();
            } else {
                showToast('Install failed', 'error');
            }
        } catch(e) {
            showToast('Install request failed', 'error');
        }
    }

    function switchMarketTab(btn, mode) {
        document.querySelectorAll('#view-market .tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentMarketCategory = mode;
        fetchMarketplaceAgents(); // Refresh list to reflect potential category changes
        showToast(`Market view: ${mode}`, 'info');
    }

    function updateMarketStats() {
        renderMarketStats(lastStatus);
    }

    async function fetchMarketplaceAgents() {
        const grid = document.getElementById('marketGrid');
        if (!grid) return;

        try {
            const res = await apiFetch(`${API}/api/agents`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            const showOffline = document.getElementById('marketShowOffline')?.checked;
            const agents = extractAgentList(data)
                .filter(a => a && typeof a === 'object')
                .map((a, idx) => ({
                    id: String(a.id || `agent-${idx + 1}`),
                    name: String(a.name || a.id || `Agent-${idx + 1}`),
                    address: String(a.address || '127.0.0.1'),
                    port: Number.isFinite(Number(a.port)) ? Number(a.port) : '-',
                    status: normalizeAgentStatus(a.status),
                    profile: String(a.profile || 'Worker'),
                    source: String(a.source || 'remote'),
                    capabilities: normalizeCapabilities(a.capabilities),
                }))
                .filter(a => {
                    const onlineStatusMatch = (a.source === 'local' || a.status === 'online' || showOffline);
                    if (!onlineStatusMatch) return false;
                    
                    // Filter by category (mode)
                    if (currentMarketCategory === 'processes') return a.profile.toLowerCase() === 'worker';
                    if (currentMarketCategory === 'services') return a.profile.toLowerCase() === 'system';
                    if (currentMarketCategory === 'counter') return a.capabilities.some(c => c.includes('economy') || c.includes('chart'));
                    if (currentMarketCategory === 'docs') return a.capabilities.includes('file_io') || a.profile.toLowerCase() === 'docs';
                    return true;
                });

            if (agents.length === 0) {
                grid.innerHTML = '<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--text-muted);">No agents found. Use "Discover" or "Add Agent".</div>';
                return;
            }

            grid.innerHTML = agents.map(a => {
                const isOnline = a.status === 'online';
                const capsHtml = a.capabilities
                    .slice(0, 2)
                    .map(c => `<span class="badge" style="background:var(--surface-600)">${escapeHtml(c)}</span>`)
                    .join('');
                const isLocal = a.source === 'local';

                return `
                    <div class="agent-card" data-agent-id="${escapeHtml(a.id)}" data-agent-name="${escapeHtml(a.name)}">
                        <div class="badge ${isOnline ? 'badge-green' : 'badge-gold'}" style="position:absolute; top:12px; right:12px;">
                            <i class="fa-solid fa-circle" style="font-size:8px; margin-right:4px;"></i> ${escapeHtml(a.status)}
                        </div>
                        <div class="agent-icon" style="color:${isOnline ? 'var(--accent-green)' : 'var(--text-muted)'}">
                            <i class="fa-solid fa-robot"></i>
                        </div>
                        <h3>${escapeHtml(a.name)}</h3>
                        <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">@ ${escapeHtml(a.address)}:${escapeHtml(a.port)}</div>
                        <div style="display:flex; gap:6px; justify-content:center; margin-bottom:16px; flex-wrap:wrap;">
                            <span class="badge" style="background:var(--surface-700)">${escapeHtml(a.profile)}</span>
                            <span class="badge" style="background:${isLocal ? 'rgba(99,102,241,0.2); color:#a5b4fc' : 'var(--surface-800)'}">${isLocal ? 'Installed' : escapeHtml(a.source)}</span>
                            ${capsHtml}
                        </div>
                        <div class="hire-actions">
                            <button class="btn btn-primary" style="flex:1; justify-content:center; font-size:11px;" onclick="inspectAgentModal('${escapeHtml(a.id)}')"><i class="fa-solid fa-eye"></i> Inspect</button>
                            ${isLocal
                                ? `<button class="btn" style="flex:1; justify-content:center; font-size:11px; color:var(--accent-green); border-color:var(--accent-green);" onclick="deployAgent('${escapeHtml(a.id)}', '${escapeHtml(a.name)}')"><i class="fa-solid fa-rocket"></i> Deploy</button>`
                                : `<button class="btn" style="flex:1; justify-content:center; font-size:11px; color:var(--accent-purple); border-color:var(--accent-purple);" onclick="installAgent('${escapeHtml(a.id)}', '${escapeHtml(a.name)}')"><i class="fa-solid fa-download"></i> Install</button>`
                            }
                        </div>
                    </div>
                `;
            }).join('');
            grid.querySelectorAll('.agent-card h3').forEach(h => setTranslatedText(h, h.textContent));
        } catch (e) {
            console.error("Failed to fetch marketplace agents:", e);
            const reason = escapeHtml(e?.message || 'unknown error');
            grid.innerHTML = `<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--risk-l3);">Error loading agents (${reason}).</div>`;
        }
        
        updateMarketStats();
        renderMarketGraph();
    }

    let marketGraphAnimation = null;
    function renderMarketGraph() {
        const canvas = document.getElementById('marketGraphCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width;
        const height = canvas.height;
        
        if (marketGraphAnimation) cancelAnimationFrame(marketGraphAnimation);

        let frame = 0;
        const nodes = [
            { x: 80, y: 70, label: 'Data', icon: '📊' },
            { x: 180, y: 70, label: 'ML Model', icon: '🧠' },
            { x: 300, y: 70, label: 'Aggregator', icon: '🔗' },
            { x: 420, y: 70, label: 'Report', icon: '📄' }
        ];

        function draw() {
            ctx.clearRect(0, 0, width, height); frame++;
            
            // Connect lines
            ctx.lineWidth = 2;
            nodes.forEach((n, i) => {
                if (i < nodes.length - 1) {
                    const next = nodes[i + 1];
                    const grad = ctx.createLinearGradient(n.x, n.y, next.x, next.y);
                    grad.addColorStop(0, 'rgba(99,102,241,0.2)');
                    grad.addColorStop(0.5, 'rgba(99,102,241,0.8)');
                    grad.addColorStop(1, 'rgba(99,102,241,0.2)');
                    ctx.strokeStyle = grad;
                    ctx.setLineDash([5, 5]);
                    ctx.lineDashOffset = -frame * 0.5;
                    ctx.beginPath();
                    ctx.moveTo(n.x, n.y);
                    ctx.lineTo(next.x, next.y);
                    ctx.stroke();
                }
            });
            ctx.setLineDash([]);

            // Draw nodes
            nodes.forEach(n => {
                const pulse = Math.sin(frame * 0.05 + nodes.indexOf(n)) * 3;
                ctx.fillStyle = 'var(--surface-700)';
                ctx.beginPath();
                ctx.arc(n.x, n.y, 22 + pulse/2, 0, Math.PI * 2);
                ctx.fill();
                ctx.strokeStyle = 'var(--primary-500)';
                ctx.lineWidth = 1.5;
                ctx.stroke();

                ctx.font = '14px sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText(n.icon, n.x, n.y + 5);
                
                ctx.fillStyle = 'var(--text-muted)';
                ctx.font = '9px var(--font-mono)';
                ctx.fillText(n.label, n.x, n.y + 35);
            });

            marketGraphAnimation = requestAnimationFrame(draw);
        }
        draw();
    }

    let agentGraphNodes = [];
    let agentGraphLinks = [];
    let selectedAgentNode = null;
    let agentGraphHover = null;
    let agentGraphDraggingNode = null;

    function fetchAgentGraph() {
        if (!cachedAgents) return;
        
        agentGraphNodes = cachedAgents.map(a => ({
            id: a.id,
            name: a.name,
            status: normalizeAgentStatus(a.status),
            x: 100 + Math.random() * 500,
            y: 80 + Math.random() * 220,
            r: 25,
            isLocal: a.source === 'local'
        }));

        // Simple link logic: connect local to others
        const local = agentGraphNodes.find(n => n.isLocal);
        agentGraphLinks = [];
        if (local) {
            agentGraphNodes.forEach(n => {
                if (n.id !== local.id) {
                    agentGraphLinks.push({ source: local.id, target: n.id });
                }
            });
        }
        
        renderAgentGraph();
        updateAgentFleetStrip();
    }

    function renderAgentGraph() {
        const canvas = document.getElementById('agentGraphCanvas');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const tooltip = document.getElementById('agentGraphTooltip');

        function draw() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            
            // Draw background grid
            ctx.strokeStyle = 'rgba(255,255,255,0.03)';
            ctx.lineWidth = 1;
            for(let x=0; x<canvas.width; x+=40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,canvas.height); ctx.stroke(); }
            for(let y=0; y<canvas.height; y+=40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(canvas.width,y); ctx.stroke(); }

            // Links
            ctx.lineWidth = 1.5;
            agentGraphLinks.forEach(l => {
                const s = agentGraphNodes.find(n => n.id === l.source);
                const t = agentGraphNodes.find(n => n.id === l.target);
                if (s && t) {
                    ctx.strokeStyle = 'rgba(99,102,241,0.25)';
                    ctx.beginPath();
                    ctx.moveTo(s.x, s.y);
                    ctx.lineTo(t.x, t.y);
                    ctx.stroke();
                }
            });

            // Nodes
            agentGraphNodes.forEach(n => {
                const isSelected = selectedAgentNode?.id === n.id;
                const isHovered = agentGraphHover?.id === n.id;
                const color = n.status === 'online' ? 'var(--accent-green)' : 'var(--accent-gold)';
                
                // Shadow
                ctx.shadowBlur = (isSelected || isHovered) ? 15 : 0;
                ctx.shadowColor = color;

                // Circle
                ctx.fillStyle = isSelected ? 'rgba(99,102,241,0.1)' : 'var(--surface-800)';
                ctx.beginPath();
                ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
                ctx.fill();
                
                ctx.strokeStyle = isSelected ? 'var(--primary-400)' : 'var(--surface-600)';
                ctx.lineWidth = isSelected ? 3 : 1;
                ctx.stroke();
                
                // Status dot
                ctx.fillStyle = color;
                ctx.beginPath();
                ctx.arc(n.x + 16, n.y - 16, 6, 0, Math.PI * 2);
                ctx.fill();
                ctx.shadowBlur = 0;

                // Icon
                ctx.font = '16px "Font Awesome 6 Free"';
                ctx.fillStyle = color;
                ctx.textAlign = 'center';
                ctx.fillText('\uf544', n.x, n.y + 6); // robot icon

                // Label
                ctx.font = '11px sans-serif';
                ctx.fillStyle = 'var(--text-primary)';
                ctx.fillText(n.name, n.x, n.y + n.r + 14);
            });
        }

        canvas.onmousemove = (e) => {
            const rect = canvas.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            const found = agentGraphNodes.find(n => Math.hypot(n.x - x, n.y - y) < n.r);
            agentGraphHover = found;
            canvas.style.cursor = found ? 'pointer' : 'grab';
            
            if (found && tooltip) {
                tooltip.style.display = 'block';
                tooltip.style.left = (x + 15) + 'px';
                tooltip.style.top = (y + 15) + 'px';
                tooltip.innerHTML = `<strong>${escapeHtml(found.name)}</strong><br>${escapeHtml(found.status)}`;
            } else if (tooltip) {
                tooltip.style.display = 'none';
            }
            draw();
        };

        canvas.onmousedown = (e) => {
            if (agentGraphHover) {
                agentGraphDraggingNode = agentGraphHover;
                selectedAgentNode = agentGraphHover;
                inspectAgent(selectedAgentNode.id);
                canvas.style.cursor = 'grabbing';
            }
        };

        window.onmouseup = () => { agentGraphDraggingNode = null; };
        
        window.onmousemove = (e) => {
            if (agentGraphDraggingNode) {
                const rect = canvas.getBoundingClientRect();
                agentGraphDraggingNode.x = e.clientX - rect.left;
                agentGraphDraggingNode.y = e.clientY - rect.top;
                draw();
            }
        }

        canvas.onclick = (e) => {
            if (agentGraphHover) {
                selectedAgentNode = agentGraphHover;
                inspectAgentBoard(selectedAgentNode.id);
            }
        };

        draw();
    }

    function updateAgentFleetStrip() {
        const strip = document.getElementById('agentFleetStrip');
        if (!strip || !cachedAgents) return;
        strip.innerHTML = cachedAgents.map(a => {
            const isOnline = normalizeAgentStatus(a.status) === 'online';
            return `
                <div class="agent-compact-card ${selectedAgentNode?.id === a.id ? 'active' : ''}" onclick="inspectAgentBoard('${a.id}')">
                    <div class="status-dot ${isOnline ? 'online' : 'away'}"></div>
                    <div style="font-weight:600;">${escapeHtml(a.name)}</div>
                    <div style="font-size:9px; color:var(--text-muted);">${escapeHtml(a.profile)}</div>
                </div>
            `;
        }).join('');
    }
    // toggleAgentViewTab removed (duplicate)

    async function inspectAgentBoard(agentId) {
        const agent = cachedAgents?.find(a => a.id === agentId);
        if (!agent) return;
        
        document.getElementById('agentDetailName').textContent = agent.name;
        document.getElementById('agentDetailMeta').textContent = `${agent.profile}  - ${agent.address}:${agent.port}`;
        const statusEl = document.getElementById('agentDetailStatus');
        if (statusEl) {
            statusEl.style.display = 'inline-block';
            statusEl.textContent = agent.status;
            statusEl.className = `badge ${normalizeAgentStatus(agent.status) === 'online' ? 'badge-green' : 'badge-gold'}`;
        }
        await loadAgentProfileDetails(agentId, agent);
        
        // Highlight in graph if not already
        if (selectedAgentNode?.id !== agentId) {
            selectedAgentNode = agentGraphNodes.find(n => n.id === agentId);
            renderAgentGraph();
        }
        updateAgentFleetStrip();
    }
    
    // Template state
    let templateData = [];
    let currentTemplateCategory = 'all';

    const getCatKey = (t) => {
        if (!t) return 'business';
        const c = String(t.category || '').toLowerCase();
        const id = String(t.id || '').toLowerCase();
        const tags = (t.tags || []).map(tg => String(tg).toLowerCase());
        
        if (c === 'marketing' || id.startsWith('mkt') || tags.includes('marketing')) return 'marketing';
        if (c === 'development' || c === 'dev' || id.startsWith('dev') || tags.includes('development')) return 'dev';
        if (c === 'devops' || id.startsWith('devops') || tags.includes('devops')) return 'devops';
        if (c === 'security' || id.startsWith('sec') || tags.includes('security')) return 'security';
        if (c === 'system' || id.startsWith('sys') || tags.includes('system')) return 'system';
        if (c === 'investment' || id.startsWith('inv') || tags.includes('investment')) return 'investment';
        if (c === 'business' || id.startsWith('biz') || tags.includes('business')) return 'business';
        if (c === 'data') return 'business';
        
        return 'business';
    };
    
    async function fetchTemplates() {
        const grid = document.getElementById('templateGrid');
        if (!grid) return;

        try {
            const res = await apiFetch(`${API}/api/templates`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            const raw = data.templates || data.items || data;
            templateData = Array.isArray(raw) ? raw : [];
            
            // Sync to AppState
            AppState.set('templates', templateData);
            renderTemplates();
        } catch (e) {
            console.error("Failed to fetch templates:", e);
            const reason = escapeHtml(e?.message || 'unknown error');
            grid.innerHTML = `<div style="grid-column: 1/-1; padding: 40px; text-align: center; color: var(--risk-l3);">Error loading templates (${reason}).</div>`;
        }
    }
    
    function renderTemplates() {
        const grid = document.getElementById('templateGrid');
        if (!grid || templateData.length === 0) {
            if (grid) grid.innerHTML = '<div style="grid-column:1/-1; padding:40px; text-align:center; color:var(--text-muted);">No templates available</div>';
            return;
        }
        
        // Filter by category and search
        let filtered = templateData;
        
        // Category filter
        if (currentTemplateCategory !== 'all') {
            filtered = filtered.filter(t => getCatKey(t) === currentTemplateCategory);
        }
        
        // Search filter
        const searchInput = document.getElementById('templateSearch');
        if (searchInput && searchInput.value) {
            const query = searchInput.value.toLowerCase();
            filtered = filtered.filter(t => 
                t.name?.toLowerCase().includes(query) || 
                t.description?.toLowerCase().includes(query) ||
                t.tags?.some(tag => tag.toLowerCase().includes(query))
            );
        }
        
        if (filtered.length === 0) {
            grid.innerHTML = '<div style="grid-column:1/-1; padding:40px; text-align:center; color:var(--text-muted);">No templates match your criteria</div>';
            return;
        }
        
        // Group by category if showing all
        if (currentTemplateCategory === 'all') {
            const categories = {
                investment: { name: 'Investment', icon: '💰', color: '#10b981', templates: [] },
                business: { name: 'Business', icon: '💼', color: '#3b82f6', templates: [] },
                dev: { name: 'Development', icon: '💻', color: '#8b5cf6', templates: [] },
                devops: { name: 'DevOps', icon: '⚙️', color: '#6366f1', templates: [] },
                marketing: { name: 'Marketing', icon: '📣', color: '#f59e0b', templates: [] },
                security: { name: 'Security', icon: '🛡️', color: '#ef4444', templates: [] },
                system: { name: 'System', icon: '💻', color: '#64748b', templates: [] }
            };
            
            filtered.forEach(t => {
                const catKey = getCatKey(t);
                if (categories[catKey]) {
                    categories[catKey].templates.push(t);
                }
            });
            
            let html = '';
            for (const [key, cat] of Object.entries(categories)) {
                if (cat.templates.length > 0) {
                    html += `
                        <div class="category-section" style="grid-column:1/-1; margin:24px 0 16px;">
                            <div class="category-header" style="display:flex; align-items:center; gap:12px; padding:12px 16px; background:linear-gradient(135deg, var(--surface-800) 0%, var(--surface-700) 100%); border-radius:8px; border-left:4px solid ${cat.color};">
                                <span style="font-size:20px;">${cat.icon}</span>
                                <h3 style="flex:1; margin:0; font-size:16px;">${cat.name}</h3>
                                <span style="font-size:12px; color:var(--text-muted); background:var(--surface-900); padding:4px 10px; border-radius:12px;">${cat.templates.length} templates</span>
                            </div>
                        </div>
                        ${cat.templates.map(t => renderTemplateCard(t)).join('')}
                    `;
                }
            }
            grid.innerHTML = html;
        } else {
            grid.innerHTML = filtered.map(t => renderTemplateCard(t)).join('');
        }

        // Update tab buttons with counts
        const allCount = templateData.length;
        const counts = { all: allCount };
        templateData.forEach(t => {
            const k = getCatKey(t);
            counts[k] = (counts[k] || 0) + 1;
        });

        document.querySelectorAll('.tab-btn').forEach(btn => {
            const cat = btn.dataset.category;
            const count = counts[cat] || 0;
            const baseText = btn.textContent.split(' (')[0];
            btn.textContent = `${baseText} (${count})`;
            btn.classList.toggle('active', cat === currentTemplateCategory);
        });
    }
    
    function renderTemplateCard(t) {
        return `
            <div class="template-card" style="background:var(--surface-800); border:1px solid var(--surface-700); border-radius:12px; padding:16px; cursor:pointer; transition:all 0.2s;" onclick="openTemplateDetail('${t.id}')">
                <div style="display:flex; justify-content:space-between; align-items:start; margin-bottom:12px;">
                    <div style="width:40px; height:40px; display:flex; align-items:center; justify-content:center; background:var(--surface-700); border-radius:8px; font-size:18px;">${t.icon || ' '}</div>
                    <span class="badge badge-green">${t.state || 'active'}</span>
                </div>
                <h3 style="font-size:14px; font-weight:600; margin:0 0 8px;">${escapeHtml(t.name || 'Untitled')}</h3>
                <p style="font-size:12px; color:var(--text-muted); margin:0 0 12px; line-height:1.4;">${escapeHtml(t.description || '')}</p>
                <div style="display:flex; gap:6px; flex-wrap:wrap; margin-bottom:12px;">
                    ${(t.tags || []).map(tag => `<span class="badge" style="background:var(--surface-600); font-size:10px;">${escapeHtml(tag)}</span>`).join('')}
                </div>
                <div style="font-size:11px; color:var(--text-muted);">
                    ${t.run_count || 0} runs  - ${t.avg_duration || 0}s avg
                </div>
            </div>
        `;
    }
    
    function filterTemplates(category) {
        currentTemplateCategory = category;
        
        // Update tab buttons
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.category === category);
        });
        
        renderTemplates();
    }
    
    function searchTemplates(query) {
        renderTemplates();
    }
    
    function createAutomation() {
        const modal = document.getElementById('createAutomationModal');
        if (modal) modal.style.display = 'flex';
    }

    function hideCreateAutomationModal() {
        const modal = document.getElementById('createAutomationModal');
        if (modal) modal.style.display = 'none';
    }

    async function submitCreateAutomation() {
        const btn = document.getElementById('createAutomationSubmitBtn');
        const name = document.getElementById('automationNameInput')?.value?.trim();
        const desc = document.getElementById('automationDescInput')?.value?.trim();
        const category = document.getElementById('automationCategoryInput')?.value || 'business';
        const cron = document.getElementById('automationCronInput')?.value?.trim();
        const tagsRaw = document.getElementById('automationTagsInput')?.value || '';
        const tags = tagsRaw.split(',').map(t => t.trim()).filter(Boolean);

        if (!name) {
            showToast('Template name is required', 'error');
            return;
        }

        if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating...'; }
        try {
            const payload = { name, description: desc, category, tags };
            if (cron) payload.cron = cron;
            // For now, add as a local template since API may not support creation yet
            templateData.push({
                id: `custom-${Date.now()}`,
                name,
                description: desc || '',
                category,
                tags,
                icon: category === 'investment' ? ' ' : category === 'dev' ? ' ' : category === 'marketing' ? ' ' : ' ',
                state: 'active',
                run_count: 0,
                avg_duration: 0
            });
            renderTemplates();
            hideCreateAutomationModal();
            showToast(`Automation "${name}" created`, 'success');
        } catch (e) {
            showToast(`Failed to create automation: ${e?.message || 'unknown error'}`, 'error');
        } finally {
            if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-plus"></i> Create'; }
        }
    }

    let currentTemplateId = null;

    async function openTemplateDetail(templateId) {
        if (!templateId) return;
        currentTemplateId = templateId;
        const modal = document.getElementById('templateDetailModal');
        if (!modal) return;

        // Try finding from cached data first
        let template = templateData.find(t => t.id === templateId);

        // Try fetching from API for more detail
        try {
            const res = await apiFetch(`${API}/api/templates/${encodeURIComponent(templateId)}`);
            if (res.ok) {
                const detail = await res.json();
                template = { ...template, ...detail };
            }
        } catch (_) {}

        if (!template) {
            showToast('Template not found', 'error');
            return;
        }

        // Populate modal
        const titleEl = document.getElementById('templateDetailTitle');
        const nameEl = document.getElementById('templateDetailName');
        const iconEl = document.getElementById('templateDetailIcon');
        const catEl = document.getElementById('templateDetailCategory');
        const stateEl = document.getElementById('templateDetailState');
        const descEl = document.getElementById('templateDetailDesc');
        const tagsEl = document.getElementById('templateDetailTags');
        const runsEl = document.getElementById('templateDetailRuns');
        const durationEl = document.getElementById('templateDetailDuration');
        const successEl = document.getElementById('templateDetailSuccessRate');
        const paramsEl = document.getElementById('templateDetailParams');
        const stepsEl = document.getElementById('templateDetailSteps');

        if (titleEl) titleEl.textContent = template.name || 'Template Detail';
        if (nameEl) nameEl.textContent = template.name || 'Untitled';
        if (iconEl) iconEl.textContent = template.icon || ' ';
        if (catEl) catEl.textContent = template.category || 'custom';
        if (stateEl) {
            stateEl.textContent = template.state || 'active';
            stateEl.className = `badge ${template.state === 'active' ? 'badge-green' : 'badge-gold'}`;
        }
        if (descEl) descEl.textContent = template.description || 'No description provided.';
        if (tagsEl) {
            tagsEl.innerHTML = (template.tags || []).map(tag =>
                `<span class="badge" style="background:var(--surface-600); font-size:11px;">${escapeHtml(tag)}</span>`
            ).join('');
        }
        if (runsEl) runsEl.textContent = template.run_count || 0;
        if (durationEl) durationEl.textContent = `${template.avg_duration || 0}s`;
        if (successEl) {
            const rate = template.success_rate;
            successEl.textContent = rate !== undefined ? `${(rate * 100).toFixed(0)}%` : ' - ';
        }

        // Parameters / Variables
        if (paramsEl) {
            const params = template.variables || template.parameters || template.params;
            if (params && (Array.isArray(params) || typeof params === 'object')) {
                if (Array.isArray(params)) {
                    paramsEl.innerHTML = params.map(p => 
                        `<div style="margin-bottom:6px; border-bottom:1px solid var(--surface-700); padding-bottom:4px;">
                            <div style="font-weight:600; color:var(--primary-400);">${escapeHtml(p.name)} <span style="font-weight:400; font-size:10px; color:var(--text-muted); opacity:0.8;">[${p.type || p.var_type || 'string'}]</span></div>
                            <div style="font-size:11px; color:var(--text-muted);">${escapeHtml(p.description || '')}</div>
                        </div>`
                    ).join('');
                } else {
                    paramsEl.innerHTML = Object.entries(params).map(([key, val]) =>
                        `<div style="margin-bottom:4px;"><span style="color:var(--primary-400);">${escapeHtml(key)}</span>: ${escapeHtml(typeof val === 'object' ? JSON.stringify(val) : String(val))}</div>`
                    ).join('');
                }
            } else {
                paramsEl.textContent = 'No parameters defined';
            }
        }

        // Steps / Nodes
        if (stepsEl) {
            const rawSteps = template.steps || (template.workflow && template.workflow.nodes) || [];
            if (Array.isArray(rawSteps) && rawSteps.length > 0) {
                stepsEl.innerHTML = rawSteps.map((s, idx) => {
                    const label = s.name || s.action || s.description || s.id || `Step ${idx + 1}`;
                    return `
                        <div style="display:flex; align-items:center; gap:10px; padding:8px 12px; background:var(--surface-800); border-radius:6px; margin-bottom:4px;">
                            <span style="font-family:var(--font-mono); font-size:11px; color:var(--text-muted); min-width:20px;">${idx + 1}</span>
                            <i class="fa-solid fa-circle-dot" style="font-size:8px; color:var(--primary-400);"></i>
                            <span style="font-size:12px;">${escapeHtml(label)}</span>
                        </div>
                    `;
                }).join('');
            } else {
                stepsEl.innerHTML = '<div style="color:var(--text-muted); font-size:12px;">No steps defined</div>';
            }
        }

        modal.style.display = 'flex';
    }

    function hideTemplateDetailModal() {
        const modal = document.getElementById('templateDetailModal');
        if (modal) modal.style.display = 'none';
    }

    function runTemplate(id) {
        const tid = id || currentTemplateId;
        if (!tid) {
            showToast('No template selected', 'error');
            return;
        }
        const template = templateData.find(t => t.id === tid);
        const name = template?.name || tid;
        
        showToast(`Running: ${name}...`, 'success');
        if (typeof hideTemplateDetailModal === 'function') hideTemplateDetailModal();
        
        appendSessionLog(`Launching workflow: ${name} [${tid}]`, 'info');
        
        // Simulate progress
        setTimeout(() => appendSessionLog(`[${tid}] Initializing environment...`, 'system'), 500);
        setTimeout(() => appendSessionLog(`[${tid}] Running step 1 of ${template?.steps?.length || '?'}: ${template?.steps?.[0]?.description || 'Initiating'}`, 'system'), 1500);
    }

    function populateTaskAssigneeOptions() {
        const select = document.getElementById('taskAssigneeInput');
        if (!select) return;

        const assignees = cachedAgents.length > 0
            ? cachedAgents
            : [{ id: selectedAgentId || 'local', name: selectedAgentName || 'local' }];

        select.innerHTML = '';

        const unassigned = document.createElement('option');
        unassigned.value = '';
        unassigned.textContent = 'Unassigned';
        select.appendChild(unassigned);

        assignees.forEach(agent => {
            const id = String(agent.id || '').trim();
            if (!id) return;
            const option = document.createElement('option');
            option.value = id;
            option.textContent = `${agent.name || id} (${id})`;
            select.appendChild(option);
        });

        if (selectedAgentId && [...select.options].some(o => o.value === selectedAgentId)) {
            select.value = selectedAgentId;
        } else {
            select.value = '';
        }
    }

    function showNewTaskModal() {
        const modal = document.getElementById('newTaskModal');
        if (!modal) return;
        populateTaskAssigneeOptions();
        modal.style.display = 'flex';
        const title = document.getElementById('taskTitleInput');
        if (title) title.focus();
    }

    function hideNewTaskModal() {
        const modal = document.getElementById('newTaskModal');
        if (modal) modal.style.display = 'none';

        const form = document.getElementById('newTaskForm');
        if (form) form.reset();

        const tags = document.getElementById('taskTagsInput');
        if (tags) tags.value = 'dashboard';

        const priority = document.getElementById('taskPriorityInput');
        if (priority) priority.value = 'Medium';
    }

    async function submitNewTask() {
        const titleInput = document.getElementById('taskTitleInput');
        const descInput = document.getElementById('taskDescriptionInput');
        const priorityInput = document.getElementById('taskPriorityInput');
        const assigneeInput = document.getElementById('taskAssigneeInput');
        const tagsInput = document.getElementById('taskTagsInput');
        const submitBtn = document.getElementById('newTaskSubmitBtn');

        const title = (titleInput?.value || '').trim();
        if (!title) {
            showToast('Task title is required', 'error');
            titleInput?.focus();
            return;
        }

        const payload = {
            title,
            description: (descInput?.value || '').trim() || 'Created from Agent Board',
            priority: priorityInput?.value || 'Medium',
            tags: (tagsInput?.value || '')
                .split(',')
                .map(t => t.trim())
                .filter(Boolean),
        };

        const assignee = (assigneeInput?.value || '').trim();
        if (assignee) payload.assignee = assignee;
        if (payload.tags.length === 0) payload.tags = ['dashboard'];

        const originalBtn = submitBtn?.innerHTML || '';
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Creating...';
        }

        try {
            const res = await apiFetch(`${API}/api/tasks`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });

            if (!res.ok) {
                let reason = `HTTP ${res.status}`;
                try {
                    const err = await res.json();
                    if (err?.error) reason = err.error;
                } catch (_) {}
                throw new Error(reason);
            }

            hideNewTaskModal();
            showToast(`Task "${title}" created`, 'success');
            fetchTasks();
        } catch (e) {
            showToast(`Failed to create task: ${e?.message || 'unknown error'}`, 'error');
        } finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalBtn;
            }
        }
    }

    // "New Task" modal triggers
    const newTaskBtn = document.getElementById('newTaskBtn');
    if (newTaskBtn) {
        newTaskBtn.addEventListener('click', showNewTaskModal);
    }

    const newTaskModal = document.getElementById('newTaskModal');
    if (newTaskModal) {
        newTaskModal.addEventListener('click', (e) => {
            if (e.target === newTaskModal) hideNewTaskModal();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && newTaskModal && newTaskModal.style.display === 'flex') {
            hideNewTaskModal();
        }
    });

    const memoryEditBtn = document.getElementById('memoryEditBtn');
    if (memoryEditBtn) {
        memoryEditBtn.addEventListener('click', () => showMemoryEditModal());
    }

    const memoryPublishBtn = document.getElementById('memoryPublishBtn');
    if (memoryPublishBtn) {
        memoryPublishBtn.addEventListener('click', () => showMemoryEditModal('lesson'));
    }

    const distillationBtn = document.getElementById('distillationBtn');
    if (distillationBtn) {
        distillationBtn.addEventListener('click', () => {
            showMemoryHistoryModal('Memory Timeline', 'Memory-specific activity entries.');
            loadMemoryHistory('memory');
        });
    }

    const gitLogBtn = document.getElementById('gitLogBtn');
    if (gitLogBtn) {
        gitLogBtn.addEventListener('click', () => {
            showMemoryHistoryModal('Git Activity', 'Recent file edit activities.');
            loadMemoryHistory('git');
        });
    }

    const memorySearchInput = document.getElementById('memorySearchInput');
    if (memorySearchInput) {
        memorySearchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const query = memorySearchInput.value.trim();
                if (query) {
                    showMemoryHistoryModal(`Search: ${query}`, 'Search results from recent activity.');
                    loadMemoryHistory('search', query);
                }
            }
        });
    }

    const memoryEditModal = document.getElementById('memoryEditModal');
    if (memoryEditModal) {
        memoryEditModal.addEventListener('click', (e) => {
            if (e.target === memoryEditModal) hideMemoryEditModal();
        });
    }

    const memoryHistoryModal = document.getElementById('memoryHistoryModal');
    if (memoryHistoryModal) {
        memoryHistoryModal.addEventListener('click', (e) => {
            if (e.target === memoryHistoryModal) hideMemoryHistoryModal();
        });
    }

    const marketShowOffline = document.getElementById('marketShowOffline');
    if (marketShowOffline) {
        marketShowOffline.addEventListener('change', fetchMarketplaceAgents);
    }

    // Dev-only auto reload: refresh browser when watch mode restarts the server.
    function initDevAutoReload() {
        const isLocal =
            window.location.hostname === '127.0.0.1' ||
            window.location.hostname === 'localhost';
        if (!isLocal) return;

        let lastUptime = null;
        let serverWasDown = false;

        const probe = async () => {
            try {
                const res = await fetch(`${API}/api/health`, { cache: 'no-store' });
                if (!res.ok) throw new Error(`health ${res.status}`);
                const data = await res.json();
            const showOffline = document.getElementById('marketShowOffline')?.checked;
                const uptime = Number(data.uptime_secs || 0);

                // If server came back after downtime, reload to get newest bundled HTML/JS.
                if (serverWasDown) {
                    window.location.reload();
                    return;
                }

                // Restart detected (uptime dropped): force full reload.
                if (lastUptime !== null && uptime + 2 < lastUptime) {
                    window.location.reload();
                    return;
                }
                lastUptime = uptime;
            } catch (_) {
                serverWasDown = true;
            }
        };

        probe();
        setInterval(probe, 1500);
    }

    //     Phase 2: AppState Subscribers                                           
    AppState.subscribe('agents', (agents) => {
        // Sync with cachedAgents so all existing code still works
        cachedAgents = agents;
    });

    AppState.subscribe('templates', (templates) => {
        templateData = templates;
        renderTemplates(); // Ensure grid updates when AppState syncs
    });

    //     Phase 6: Settings Tab System                                            
    function switchSettingsTab(tabId) {
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
    }

    async function loadSecurityTab() {
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

    function copyApiKey() {
        const keyEl = document.getElementById('settingsApiKey');
        if (!keyEl) return;
        navigator.clipboard.writeText(keyEl.textContent).then(() => {
            showToast('API Key copied to clipboard', 'success');
        }).catch(() => {
            showToast('Failed to copy. Please select and copy manually', 'error');
        });
    }

    function regenerateApiKey() {
        if (!confirm('Regenerating the API key will disconnect all active sessions. Continue?')) return;
        showToast('API key rotation is managed by node restart', 'info');
    }

    //     Phase 5: Redirect legacy HTML routes to SPA hash routes                 
    function ensureSpaRoute() {
        const hash = window.location.hash;
        // If hash already set, trust it
        if (hash && hash !== '#') return;

        // Map legacy URL paths to SPA hash routes
        const path = window.location.pathname.replace(/\.html$/, '').replace(/^\//, '');
        const pathMap = {
            '': 'dashboard',
            'index': 'dashboard',
            'automations': 'automations',
            'marketplace': 'market',
            'settings': 'settings',
            'extensions': 'extensions',
            'memory': 'memory',
            'agents': 'board',
            'chat': 'chat',
            'aichat': 'aichat',
        };
        const target = pathMap[path] || 'dashboard';
        window.location.hash = `#${target}`;
    }

    // Expose handlers for inline HTML event attributes
    Object.assign(window, {
        closeExtModal,
        confirmDeploy,
        copyApiKey,
        createAutomation,
        deployAgent,
        discoverAgents,
        fetchAgentGraph,
        filterExtCat,
        filterTemplates,
        hideAddAgentModal,
        hideCreateAutomationModal,
        hideMemoryEditModal,
        hideMemoryHistoryModal,
        hideNewTaskModal,
        hideRentPolicyModal,
        hideTemplateDetailModal,
        inspectAgentBoard,
        inspectAgentModal,
        installAgent,
        openAddModuleModal,
        openExtConfigModal,
        openExtLogsModal,
        openTemplateDetail,
        refreshExtensions,
        regenerateApiKey,
        resetGraphZoom,
        runExtension,
        runTemplate,
        saveExtConfig,
        saveNewModule,
        searchExtensions,
        searchTemplates,
        selectAgentDetail,
        setActiveView,
        showAddAgentModal,
        submitAddAgent,
        submitCreateAutomation,
        submitMemoryEdit,
        submitNewTask,
        submitRentPolicy,
        switchMarketTab,
        switchMemoryTab,
        switchSettingsTab,
        toggleAgentViewTab,
        toggleGraphMode,
        toggleMode,
        showToast,
    });
    // AppState Subscribers
    AppState.subscribe('status', (status) => {
        lastStatus = status;
        if (typeof renderEconomy === 'function') renderEconomy(status);
        if (typeof updateMarketStats === 'function') updateMarketStats();
    });

    // Initialize
    initChat({ getCurrentMode: () => currentMode, appendSessionLog, renderEconomy, fetchMemory });
    initAIChat();
    initDevAutoReload();
    fetchStatus();
    fetchTasks();
    fetchMemory();
    fetchExtensions();
    fetchExtReadiness();
    updateContextPanel(selectedAgentId, 'Agent');
    ensureSpaRoute();

    //     Phase 7: Extensions AppState subscriber                              
    AppState.subscribe('extensions', (modules) => {
        extModules = modules;
        renderExtGrid();
        updateExtCatCounts();
    });

    // Close extension + agent modals on overlay click
    ['extConfigModal','extLogsModal','extAddModal','agentInspectModal','agentDeployModal'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.addEventListener('click', (e) => {
            if (e.target === el) closeExtModal(id);
        });
    });






