import { API, AppState, apiFetch, showToast, setTranslatedText } from './core.js';
import * as chat from './chat.js';
import * as ext from './extensions.js';
import * as tmpl from './templates.js';
import * as task from './tasks.js';
import * as market from './marketplace.js';
import * as board from './agent-board.js';
import * as mem from './memory.js';
import * as mission from './mission.js';
import * as settings from './settings.js';
import * as fleet from './v2.js';

// Application State
let currentMode = 'sanctum';
let selectedAgentId = 'local';
let selectedAgentName = 'local';

function toggleMode() {
    const modes = ['sanctum', 'automation', 'fleet', 'market'];
    let idx = modes.indexOf(currentMode);
    idx = (idx + 1) % modes.length;
    setMode(modes[idx]);
    showToast(`Switched to ${modes[idx].toUpperCase()} mode`, "info");
}

function selectAgent(id) {
    selectedAgentId = id;
    const agent = cachedAgents.find(a => a.peer_id === id);
    if (agent) selectedAgentName = agent.device_name;
    
    showToast(`Focusing on agent: ${selectedAgentName}`, "info");
}
export let cachedAgents = [];

/**
 * Fetch All Agents (Fleet)
 */
async function fetchFleet() {
    try {
        const res = await apiFetch(`${API}/api/agents`);
        if (res.ok) {
            const data = await res.json();
            cachedAgents = data.agents || [];
            console.log(`[Fleet] Loaded ${cachedAgents.length} agents`);
            
            // Sync with other modules
            if (typeof board.fetchAgentGraph === 'function') board.fetchAgentGraph(cachedAgents);
            // Also notify mission.js to render the grid
            if (typeof mission.renderFleetDashboard === 'function') mission.renderFleetDashboard(cachedAgents);
        }
    } catch (e) {
        console.error('[Fleet] Fetch failed:', e);
    }
}

// Helper functions (Utilities)
function normalizeAgentStatus(status) {
    return String(status || 'offline').toLowerCase();
}

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// View Logic
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
        'view-aichat': 'Intoran AI',
        'view-fleet': 'Fleet Governance'
    };
    return map[viewId] || 'EdgeClaw';
}

function updateBreadcrumb(viewId) {
    const viewBreadcrumb = document.getElementById('view-breadcrumb');
    if (!viewBreadcrumb) return;
    viewBreadcrumb.textContent = viewNameFromId(viewId);
}

function setMode(mode) {
    currentMode = mode;
    const modeIndicator = document.getElementById('mode-indicator');
    const modeIcon = document.getElementById('mode-icon');
    const modeText = document.getElementById('mode-text');
    if (modeIndicator) modeIndicator.dataset.mode = mode;
    if (modeIcon) {
        modeIcon.className = mode === 'market' ? 'fa-solid fa-shop' : 
                          mode === 'automation' ? 'fa-solid fa-bolt' : 
                          mode === 'fleet' ? 'fa-solid fa-users' : 'fa-solid fa-shield-halved';
    }
    if (modeText) {
        modeText.textContent = mode === 'market' ? 'TRADING MODE' : 
                               mode === 'automation' ? 'AUTO MODE' : 
                               mode === 'fleet' ? 'FLEET MODE' : 'SANCTUM MODE';
    }
}

function applyViewSideEffects(viewId) {
    if (viewId === 'view-market') {
        setMode('market');
        market.fetchMarketplaceAgents();
    } else if (viewId === 'view-dashboard') {
        setMode('sanctum');
        mission.fetchStatus();
    } else if (viewId === 'view-board') {
        task.fetchTasks(selectedAgentId);
        board.fetchAgentGraph(cachedAgents);
    } else if (viewId === 'view-memory') {
        mem.fetchMemory();
    } else if (viewId === 'view-automations') {
        setMode('automation');
        tmpl.fetchTemplates();
    } else if (viewId === 'view-fleet') {
        setMode('fleet');
        if (window.fetchGroups) window.fetchGroups();
    } else if (viewId === 'view-settings') {
        setMode('sanctum');
        settings.loadSettingsIdentity();
    } else if (viewId === 'view-extensions') {
        setMode('sanctum');
        ext.fetchExtensions();
        ext.fetchExtReadiness();
        ext.startExtReadinessTimer();
    } else {
        setMode('sanctum');
    }
}

function setActiveView(viewId, options = {}) {
    const { updateHash = true, extensionFilter = null } = options;
    const targetView = document.getElementById(viewId);
    if (!targetView) return;

    if (viewId === 'view-extensions' && !extensionFilter) {
        ext.setExtCurrentFilter('all');
    } else if (extensionFilter) {
        ext.setExtCurrentFilter(extensionFilter);
    }

    document.querySelectorAll('.nav-item, .nav-subitem').forEach(n => n.classList.remove('active'));
    const mainNav = Array.from(document.querySelectorAll('.nav-item')).find(n => n.dataset.target === viewId);
    if (mainNav) mainNav.classList.add('active');

    if (viewId === 'view-extensions' && extensionFilter) {
        const sub = Array.from(document.querySelectorAll('.nav-subitem')).find(n => n.dataset.extension === extensionFilter);
        if (sub) sub.classList.add('active');
        const catBtn = document.querySelector(`.ext-cat-btn[data-cat="${extensionFilter}"]`);
        if (catBtn) ext.filterExtCat(extensionFilter, catBtn);
    }

    document.querySelectorAll('.view-content').forEach(v => v.classList.remove('active'));
    targetView.classList.add('active');

    if (updateHash) {
        const hashValue = viewId.replace('view-', '');
        const suffix = (viewId === 'view-extensions' && ext.getExtCurrentFilter() !== 'all') ? `:${ext.getExtCurrentFilter()}` : '';
        window.location.hash = `${hashValue}${suffix}`;
    }

    updateBreadcrumb(viewId);
    applyViewSideEffects(viewId);
    
    // Trigger module-specific logic if registered
    const viewLogic = AppState.get('views')?.[viewId];
    if (viewLogic) {
        if (typeof viewLogic.fetch === 'function') viewLogic.fetch();
        if (typeof viewLogic.render === 'function') viewLogic.render();
    }

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

// Dev-only auto reload
function initDevAutoReload() {
    const isLocal = window.location.hostname === '127.0.0.1' || window.location.hostname === 'localhost';
    if (!isLocal) return;

    let lastUptime = null;
    let serverWasDown = false;

    const probe = async () => {
        try {
            const res = await fetch(`${API}/api/health`, { cache: 'no-store' });
            if (!res.ok) throw new Error(`health ${res.status}`);
            const data = await res.json();
            const uptime = Number(data.uptime_secs || 0);
            if (serverWasDown || (lastUptime !== null && uptime + 2 < lastUptime)) {
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

// AppState Subscribers
AppState.subscribe('agents', (agents) => {
    cachedAgents = agents;
    window.cachedAgents = agents; // For modules that need it
    board.updateAgentFleetStrip(agents);
});

AppState.subscribe('templates', (templates) => {
    tmpl.setTemplateData(templates);
    tmpl.renderTemplates();
});

AppState.subscribe('extensions', (modules) => {
    ext.setExtModules(modules);
    ext.renderExtGrid();
    ext.updateExtCatCounts();
});

AppState.subscribe('status', (status) => {
    mission.renderStatus(status);
    if (typeof market.updateMarketStats === 'function') market.updateMarketStats();
});

// Expose handlers for inline HTML event attributes
Object.assign(window, {
    // Core/View
    setActiveView,
    showToast,
    escapeHtml,
    setTranslatedText,
    toggleMode,
    selectAgent,
    closeModal: (id) => {
        const el = document.getElementById(id);
        if (el) el.classList.remove('open');
    },
    
    // Extensions
    closeExtModal: ext.closeExtModal,
    filterExtCat: ext.filterExtCat,
    openAddModuleModal: ext.openAddModuleModal,
    openExtConfigModal: ext.openExtConfigModal,
    openExtLogsModal: ext.openExtLogsModal,
    refreshExtensions: ext.refreshExtensions,
    runExtension: ext.runExtension,
    saveExtConfig: ext.saveExtConfig,
    saveNewModule: ext.saveNewModule,
    searchExtensions: ext.searchExtensions,
    
    // Templates
    createAutomation: tmpl.createAutomation,
    filterTemplates: tmpl.filterTemplates,
    hideCreateAutomationModal: tmpl.hideCreateAutomationModal,
    hideTemplateDetailModal: tmpl.hideTemplateDetailModal,
    openTemplateDetail: tmpl.openTemplateDetail,
    runTemplate: tmpl.runTemplate,
    searchTemplates: tmpl.searchTemplates,
    submitCreateAutomation: tmpl.submitCreateAutomation,
    
    // Tasks
    fetchTasks: () => task.fetchTasks(selectedAgentId, (e) => e.dataTransfer.setData('text/plain', e.target.id)),
    hideNewTaskModal: task.hideNewTaskModal,
    showNewTaskModal: () => task.showNewTaskModal(cachedAgents, selectedAgentId),
    submitNewTask: task.submitNewTask,
    
    // Marketplace
    confirmDeploy: market.confirmDeploy,
    deployAgent: market.deployAgent,
    fetchMarketplaceAgents: market.fetchMarketplaceAgents,
    inspectAgentModal: market.inspectAgentModal,
    installAgent: market.installAgent,
    switchMarketTab: market.switchMarketTab,
    submitRentPolicy: market.submitRentPolicy,
    hideRentPolicyModal: () => {
        const el = document.getElementById('rentPolicyModal');
        if (el) el.style.display = 'none';
    },
    
    // Board
    discoverAgents: board.discoverAgents,
    fetchAgentGraph: () => board.fetchAgentGraph(cachedAgents),
    inspectAgentBoard: (id) => board.inspectAgentBoard(id, cachedAgents),
    updateAgentFleetStrip: () => board.updateAgentFleetStrip(cachedAgents),
    hideAddAgentModal: board.hideAddAgentModal,
    showAddAgentModal: board.showAddAgentModal,
    submitAddAgent: board.submitAddAgent,
    toggleAgentViewTab: board.toggleAgentViewTab,
    
    // Chat
    showChatHelp: chat.showChatHelp,
    
    // Memory
    fetchMemory: mem.fetchMemory,
    hideMemoryEditModal: mem.hideMemoryEditModal,
    hideMemoryHistoryModal: mem.hideMemoryHistoryModal,
    showMemoryEditModal: mem.showMemoryEditModal,
    submitMemoryEdit: mem.submitMemoryEdit,
    switchMemoryTab: mem.switchMemoryTab,
    selectMemoryTier: mem.selectMemoryTier,
    resetGraphZoom: mem.resetGraphZoom,
    toggleGraphMode: mem.toggleGraphMode,
    
    // Settings
    copyApiKey: settings.copyApiKey,
    regenerateApiKey: settings.regenerateApiKey,
    switchSettingsTab: settings.switchSettingsTab,
    
    // Mission
    fetchStatus: mission.fetchStatus,

    // Fleet/Governance
    showCreateGroupModal: fleet.showCreateGroupModal,
    syncAllPolicies: fleet.syncAllPolicies,
    openGroupSettings: fleet.openGroupSettings,
    addGroupPolicyOverride: fleet.addGroupPolicyOverride,
    removeGsOverride: fleet.removeGsOverride,
    saveGroupSettings: fleet.saveGroupSettings,
});

// Initialize
async function init() {
    console.log('[Dashboard] Initializing engine...');
    
    // 1. Setup global state
    try {
        console.log('[Dashboard] Fetching initial state...');
        await mission.fetchStatus();
        console.log('[Dashboard] Status fetched.');
        
        await fetchFleet();
        console.log('[Dashboard] Fleet fetched.');
        
        await fleet.fetchGroups();
        console.log('[Dashboard] Teams fetched.');
        
        await mem.fetchMemory();
        console.log('[Dashboard] Memory fetched.');
        
        await tmpl.fetchTemplates();
        console.log('[Dashboard] Templates fetched.');
    } catch (e) {
        console.error('[Dashboard] Initial state fetch failure:', e);
    }

    // 2. Component Init
    try {
        console.log('[Dashboard] Registering partial components...');
        AppState.register('view-dashboard', {
            render: () => {
                mission.renderStatus(mission.lastStatus);
                mission.renderMissionOverview(mission.lastActivityStats || { total_entries: 0 });
                // Also trigger fleet render
                mission.renderFleetDashboard(cachedAgents);
            },
            fetch: mission.fetchStatus
        });
        AppState.register('view-board', {
            render: () => {
                board.fetchAgentGraph(cachedAgents);
                board.updateAgentFleetStrip(cachedAgents);
            },
            fetch: () => task.fetchTasks(selectedAgentId)
        });
        AppState.register('view-fleet', {
            render: () => fleet.fetchGroups(),
            fetch: fleet.fetchGroups
        });
        AppState.register('view-memory', {
            render: () => mem.renderMemory(mem.lastMemory),
            fetch: mem.fetchMemory
        });
        AppState.register('view-market', {
            render: () => market.renderMarketGraph(),
            fetch: market.fetchMarketplaceAgents
        });
        AppState.register('view-automations', {
            render: () => tmpl.renderTemplates(),
            fetch: tmpl.fetchTemplates
        });
        AppState.register('view-extensions', {
            render: () => ext.renderExtGrid(),
            fetch: () => { ext.fetchExtensions(); ext.fetchExtReadiness(); }
        });
        AppState.register('view-settings', {
            render: () => settings.loadSettingsIdentity(),
            fetch: settings.loadSettingsIdentity
        });
        chat.initChat({ 
            getCurrentMode: () => currentMode, 
            appendSessionLog: (msg, tone) => {
                const log = document.getElementById('sessionLog');
                if (!log) return;
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                if (tone === 'warn') entry.style.color = 'var(--accent-gold)';
                if (tone === 'error') entry.style.color = 'var(--accent-red)';
                entry.innerHTML = `<span class="log-time">${time}</span> <span>${escapeHtml(msg)}</span>`;
                log.prepend(entry);
            }, 
            renderEconomy: mission.renderStatus, 
            fetchMemory: mem.fetchMemory 
        });
        chat.initAIChat();
    } catch (e) {
        console.warn('Chat initialization failed:', e);
    }

    // 3. Navigation Listeners
    document.querySelectorAll('.nav-item[data-target], .nav-subitem[data-target], .logo').forEach(item => {
        item.addEventListener('click', () => {
            const target = item.dataset.target || (item.classList.contains('logo') ? 'view-dashboard' : null);
            if (target) {
                setActiveView(target);
            }
        });
    });

    // 4. Global Listeners
    window.addEventListener('hashchange', activateViewFromHash);
    
    // 5. Initial View
    activateViewFromHash();
    
    // 6. Periodic Updates
    setInterval(() => mission.fetchStatus(), 10000);
}

// Start
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}
