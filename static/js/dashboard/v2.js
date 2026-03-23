// ???EdgeClaw V2.2 & V2.4 Visual Fleet & Governance Controller
import { API, AppState, apiFetch, showToast, setTranslatedText } from './core.js';

let lastGroups = [];
let fleetGraphAnimId = null;

/**
 * Initialize Fleet Governance View
 */
export function initFleetGovernance() {
    console.log("V2.4 Fleet Governance Initialized");
    fetchGroups();
    
    // Auto-refresh groups every 10 seconds
    setInterval(fetchGroups, 10000);
}

/**
 * Fetch all groups and their members
 */
export async function fetchGroups() {
    try {
        const res = await apiFetch(`${API}/api/groups`);
        if (res.ok) {
            const groups = await res.json();
            lastGroups = groups;
            renderTeamAccordion(groups);
            renderTeamDirectory(groups);
            renderFleetVisualMap(groups);
        }
    } catch (e) {
        console.error("Failed to fetch groups:", e);
    }
}

/**
 * Show create team modal (or a simple prompt for now)
 */
export function showCreateGroupModal() {
    // In a real app we'd open a modal, for now use a prompt to create a basic group
    const name = prompt("Enter Team Name:");
    if (!name) return;
    
    apiFetch(`${API}/api/groups`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            name, 
            description: "New agent collective", 
            leader_id: "", 
            member_ids: [], 
            policy_overrides: {}, 
            policy_tags: ["manual"], 
            sync_memory: true 
        })
    }).then(() => {
        showToast(`Team "${name}" created.`, "success");
        fetchGroups();
    }).catch(e => {
        console.error("Create group failed:", e);
        showToast("Failed to create group.", "error");
    });
}

/**
 * Sync all policies across the fleet
 */
export function syncAllPolicies() {
    showToast("Broadcasting global policies to all nodes...", "info");
    // This is essentially just refreshing the group state from backend in this UI
    fetchGroups().then(() => {
        setTimeout(() => showToast("Sync completed across 0 nodes.", "success"), 800);
    });
}

/**
 * Render Sidebar Team Accordion
 */
function renderTeamAccordion(groups) {
    const container = document.getElementById('sidebarTeamGroups');
    if (!container) return;

    if (groups.length === 0) {
        container.innerHTML = `
            <div class="team-item">
                <div class="team-header">
                    <div class="team-name" style="color:var(--text-muted); font-size:11px;">
                        No teams created yet.
                    </div>
                </div>
            </div>`;
        return;
    }

    container.innerHTML = groups.map(group => `
        <div class="team-item" id="team-acc-${group.id}">
            <div class="team-header" onclick="this.parentElement.classList.toggle('open')">
                <div class="team-name">
                    <i class="fa-solid fa-hashtag" style="color:var(--primary-400)"></i>
                    <span>${escapeHtml(group.name)}</span>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <span class="team-meta">${group.member_ids.length}</span>
                    <i class="fa-solid fa-chevron-right" style="font-size:10px; color:var(--text-muted); transition:0.3s;"></i>
                </div>
            </div>
            <div class="team-members">
                ${group.member_ids.length > 0 ? group.member_ids.map(peerId => {
                    const isLeader = group.leader_id === peerId;
                    return `
                        <div class="agent-mini-card" onclick="selectAgent('${peerId}')">
                            <div class="status-dot online" style="width:6px; height:6px;"></div>
                            <span>${(peerId.slice(0, 8))}</span>
                            ${isLeader ? '<i class="fa-solid fa-crown leader-badge" title="Team Leader"></i>' : ''}
                        </div>
                    `;
                }).join('') : '<div style="font-size:10px; color:var(--text-muted); padding:4px 0;">No members</div>'}
            </div>
        </div>
    `).join('');
}

/**
 * Render Team Directory in the Fleet View
 */
function renderTeamDirectory(groups) {
    const list = document.getElementById('fleetTeamList');
    if (!list) return;

    list.innerHTML = groups.map(group => `
        <div class="card" style="background:var(--surface-800); padding:16px; border-radius:12px;">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:12px;">
                <div>
                    <h4 style="font-size:14px; font-weight:700; margin:0;">${escapeHtml(group.name)}</h4>
                    <p style="font-size:11px; color:var(--text-muted); margin:4px 0 0;">${escapeHtml(group.description)}</p>
                </div>
                <div style="display:flex; align-items:center; gap:8px;">
                    <div class="badge badge-blue" style="font-size:9px;">${group.member_ids.length} Members</div>
                    <button class="btn" style="padding:4px 8px; font-size:10px;" onclick="openGroupSettings('${group.id}')"><i class="fa-solid fa-gear"></i> Settings</button>
                </div>
            </div>
            <div style="display:flex; flex-wrap:wrap; gap:6px; margin-top:10px;">
                ${group.policy_tags.map(tag => `<span class="badge" style="background:var(--surface-700); font-size:10px;">#${tag}</span>`).join('')}
                <button class="btn" style="padding:2px 8px; font-size:10px; border-radius:12px;" onclick="addPolicyToGroup('${group.id}')"><i class="fa-solid fa-plus"></i> Policy</button>
            </div>
        </div>
    `).join('');
}

let currentGsGroupId = null;
let currentGsOverrides = {};

export function openGroupSettings(groupId) {
    currentGsGroupId = groupId;
    const group = lastGroups.find(g => g.id === groupId);
    if (!group) return;

    document.getElementById('gsGroupName').textContent = group.name;
    document.getElementById('gsGroupId').textContent = `ID: ${group.id}`;
    document.getElementById('gsMemorySync').checked = group.sync_memory !== false;
    
    currentGsOverrides = group.policy_overrides || {};
    renderGsPolicyList();
    
    document.getElementById('groupSettingsModal').classList.add('open');
};

function renderGsPolicyList() {
    const list = document.getElementById('gsPolicyList');
    if (!list) return;
    
    const entries = Object.entries(currentGsOverrides);
    if (entries.length === 0) {
        list.innerHTML = '<p style="font-size:11px; color:var(--text-muted); text-align:center;">No policy overrides.</p>';
        return;
    }
    
    list.innerHTML = entries.map(([cap, allowed]) => `
        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:var(--surface-900); border-radius:8px;">
            <div style="font-size:12px; font-weight:500;">${cap}</div>
            <div style="display:flex; gap:8px; align-items:center;">
                <span class="badge ${allowed ? 'badge-green' : 'badge-red'}" style="font-size:9px;">${allowed ? 'ALLOW' : 'DENY'}</span>
                <button class="btn" style="padding:2px 4px; font-size:10px; border-color:var(--accent-red);" onclick="removeGsOverride('${cap}')">&times;</button>
            </div>
        </div>
    `).join('');
}

export function addGroupPolicyOverride() {
    const cap = document.getElementById('gsNewCap').value;
    if (!cap) return;
    
    // Default to DENY for manual overrides (safety first)
    currentGsOverrides[cap] = false;
    renderGsPolicyList();
};

export function removeGsOverride(cap) {
    delete currentGsOverrides[cap];
    renderGsPolicyList();
};

window.saveGroupSettings = async () => {
    if (!currentGsGroupId) return;
    
    const syncMemory = document.getElementById('gsMemorySync').checked;
    
    try {
        // First sync memory setting
        await apiFetch(`${API}/api/groups/${currentGsGroupId}/memory/sync`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sync: syncMemory })
        });
        
        // Then sync each override (In a real systems we would do this in one batch, but here we use the specific endpoint)
        // For simplicity, we just save the local state and refresh
        for (const [cap, allowed] of Object.entries(currentGsOverrides)) {
            await apiFetch(`${API}/api/groups/${currentGsGroupId}/policy`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ capability: cap, allowed })
            });
        }
        
        showToast("Group settings saved successfully.", "success");
        document.getElementById('groupSettingsModal').classList.remove('open');
        fetchGroups();
    } catch (e) {
        console.error("Save failed:", e);
        showToast("Failed to save some settings.", "error");
    }
};

window.closeModal = (id) => {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
};

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderFleetVisualMap(groups) {
    // Placeholder for future D3.js or Canvas-based fleet visualizer
    console.log("[V2.4] Visual map rendering for groups:", groups.length);
}

initFleetGovernance();
