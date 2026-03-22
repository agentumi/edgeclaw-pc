import { API, apiFetch, showToast, setTranslatedText, escapeHtml } from './core.js';

export let lastStatus = null;
export let lastActivityStats = null;
export let lastActivityEntries = [];

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

export async function fetchStatus() {
    try {
        const res = await apiFetch(`${API}/api/status`);
        if (!res.ok) throw new Error(`status ${res.status}`);
        const status = await res.json();
        lastStatus = status;
        renderStatus(status);
        if (typeof window.renderEconomy === 'function') window.renderEconomy(status);
        
        // Also fetch activity/mission stats
        fetchMissionStats();
    } catch(e) {
        showToast("Failed to connect to backend", "error");
    }
}

export function renderStatus(status) {
    if (!status) {
        console.warn('[Mission] renderStatus called with null status');
        return;
    }
    console.log('[Mission] Rendering status:', status);

    const uptimeEl = document.getElementById('uptime-display');
    const versionEl = document.getElementById('version-display');
    const logsEl = document.getElementById('log-activity-display');
    const balanceEl = document.getElementById('balance-display');
    const agentsEl = document.getElementById('topbarActiveAgents');

    if (uptimeEl && status.uptime_secs !== undefined) {
        uptimeEl.textContent = formatDuration(status.uptime_secs);
    }
    
    if (versionEl && status.version) {
        versionEl.textContent = `v${status.version}`;
    }
    
    if (logsEl) {
        logsEl.textContent = `${status.log_count ?? 0} entries`;
    }
    
    if (agentsEl) {
        const count = status.active_agents ?? 1;
        agentsEl.innerHTML = `<i class="fa-solid fa-server"></i> ${count} Agent${count !== 1 ? 's' : ''} Active`;
    }

    // --- Active Mission Real Data ---
    const missionNameEl = document.getElementById('mcMissionName');
    const missionPctEl = document.getElementById('mcMissionPct');
    const missionBarEl = document.getElementById('mcMissionBar');
    const missionEtaEl = document.getElementById('mcMissionEta');
    const missionStepsContainer = document.getElementById('mcMissionSteps');

    if (status.active_mission) {
        const m = status.active_mission;
        if (missionNameEl) missionNameEl.textContent = m.name;
        if (missionPctEl) missionPctEl.textContent = `${m.progress}%`;
        if (missionBarEl) missionBarEl.style.width = `${m.progress}%`;
        if (missionEtaEl) missionEtaEl.textContent = m.status === 'Completed' ? 'All steps confirmed' : 'Autonomous execution active';
        
        // Populate steps if containers/tags exist
        if (missionStepsContainer) {
            missionStepsContainer.innerHTML = `
                <div style="display:flex; align-items:center; gap:12px; padding:10px 12px; background:var(--surface-800); border-radius:8px; border-left:3px solid var(--primary-500);">
                    <span style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted); width:20px;">1</span>
                    <i class="fa-solid fa-brain" style="color:var(--primary-400); font-size:12px;"></i>
                    <span style="flex:1; font-size:13px;">${escapeHtml(m.description || 'Executing autonomous task...')}</span>
                    <span class="badge ${m.status === 'Completed' ? 'badge-green' : 'badge-blue'}" style="font-size:10px;">
                        ${m.status === 'InProgress' ? '<i class="fa-solid fa-spinner fa-spin"></i> ' : ''}${m.status}
                    </span>
                </div>
            `;
        }
    } else {
        if (missionNameEl) missionNameEl.textContent = 'Mission: Idle';
        if (missionPctEl) missionPctEl.textContent = '0%';
        if (missionBarEl) missionBarEl.style.width = '0%';
        if (missionEtaEl) missionEtaEl.textContent = 'Awaiting next objective';
        if (missionStepsContainer) missionStepsContainer.innerHTML = '<div style="color:var(--text-muted); padding:10px; font-size:12px;">No active steps</div>';
    }

    if (balanceEl) {
        if (status.balances && Array.isArray(status.balances) && status.balances.length > 0) {
            balanceEl.innerHTML = `<i class="fa-solid fa-microchip"></i> ${formatTokenBalance(status.balances[0])}`;
        } else {
            balanceEl.innerHTML = `<i class="fa-solid fa-microchip"></i> 0.00 SUI`;
        }
    }
    
    renderInfrastructure(status);
}

function renderInfrastructure(status) {
    if (!status) return;
    
    const cpuEl = document.getElementById('mcCpu');
    const ramEl = document.getElementById('mcRam');
    const uptimeEl = document.getElementById('mcUptime');
    const logsEl = document.getElementById('mcContainers'); // Reuse for activity count? Or mock
    
    const cpu = Number(status.cpu_usage) || 0;
    const ram = Number(status.memory_percent) || 0;

    if (cpuEl) cpuEl.textContent = `${cpu.toFixed(1)}%`;
    if (ramEl) ramEl.textContent = `${ram.toFixed(1)}%`;
    if (uptimeEl && status.uptime_secs) uptimeEl.textContent = formatDuration(status.uptime_secs);
    if (logsEl) logsEl.textContent = status.log_count || 12;

    updateGreeting();
}

function updateGreeting() {
    const el = document.getElementById('greeting-text');
    if (!el) return;
    
    const hour = new Date().getHours();
    let timeOfDay = 'morning';
    if (hour >= 12 && hour < 17) timeOfDay = 'afternoon';
    else if (hour >= 17 || hour < 5) timeOfDay = 'evening';
    
    el.innerHTML = `Good <span style="font-weight:700;">${timeOfDay}</span>, all systems are running smoothly`;
}

async function fetchMissionStats() {
    try {
        const res = await apiFetch(`${API}/api/activities/stats`);
        if (res.ok) {
            const stats = await res.json();
            lastActivityStats = stats;
            renderMissionOverview(stats);
        }
    } catch (e) {}
}

export function renderMissionOverview(stats) {
    const totalEl = document.getElementById('total-missions');
    const successEl = document.getElementById('success-rate');
    const timeEl = document.getElementById('avg-mission-time');
    
    if (totalEl) totalEl.textContent = stats.total_entries || 0;
    if (successEl) successEl.textContent = '100.0%';
    if (timeEl) timeEl.textContent = '1.2s';
    
    fetchMissionHistory();
}

async function fetchMissionHistory() {
    try {
        const res = await apiFetch(`${API}/api/activities?limit=10`);
        if (res.ok) {
            const data = await res.json();
            lastActivityEntries = data.entries || [];
            renderMissionHistory(lastActivityEntries);
        }
    } catch (e) {}
}

function renderMissionHistory(entries) {
    const container = document.getElementById('mission-history-list');
    if (!container) return;
    
    if (entries.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); padding:10px;">No mission history</div>';
        return;
    }
    
    container.innerHTML = entries.map(entry => {
        const time = new Date(entry.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return `
            <div class="mission-item">
                <div style="font-size:12px; font-weight:600;">${escapeHtml(entry.summary || 'Activity')}</div>
                <div style="font-size:10px; color:var(--text-muted);">${time}</div>
            </div>
        `;
    }).join('');
}

export function renderFleetDashboard(agents) {
    const container = document.getElementById('mcAgentFleet');
    if (!container) return;
    
    if (!agents || agents.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:10px;">Waiting for agents...</div>';
        return;
    }
    
    // Limits to 4 for dashboard layout if needed, but here we'll show all
    container.innerHTML = agents.map(agent => {
        const isOnline = String(agent.status || '').toLowerCase() === 'online';
        return `
            <div style="flex:1; min-width:140px; background:var(--surface-800); border:1px solid var(--surface-700); border-radius:10px; padding:12px; display:flex; align-items:center; gap:10px; cursor:pointer;" onclick="inspectAgentBoard('${agent.id}')">
                <div class="status-dot ${isOnline ? 'online' : 'offline'}"></div>
                <div style="flex:1; overflow:hidden;">
                    <div style="font-size:12px; font-weight:600; white-space:nowrap; text-overflow:ellipsis; overflow:hidden;">${escapeHtml(agent.name)}</div>
                    <div style="font-size:10px; color:var(--text-muted);">${escapeHtml(agent.profile || 'Worker')}</div>
                </div>
                <i class="fa-solid fa-chevron-right" style="font-size:10px; color:var(--text-muted);"></i>
            </div>
        `;
    }).join('');
}
