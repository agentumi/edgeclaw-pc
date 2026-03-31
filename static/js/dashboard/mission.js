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
        // V3: Fetch quantum hub stats
        fetchQuantumStats();
        // P7-09: Fetch persona card data
        fetchPersonaCard();
        // P7-07: Fetch quantum state visualizer data
        fetchQuantumStateVisualizer();
        // P7-10: Fetch scheduler jobs
        fetchSchedulerJobs();
        // P5: Fetch governance dashboard
        fetchGovernanceDashboard();
        // P3-08: Fetch viral diffusion stats
        fetchDiffusionStats();
        // P1-12: Fetch communication hub stats
        fetchCommHubStats();
    } catch(e) {
        showToast("Failed to connect to backend", "error");
    }
}

// ─── V3 Quantum/Fleet Process Monitor ───────────────────────

async function fetchQuantumStats() {
    try {
        const [statsRes, typeRes, patternsRes] = await Promise.all([
            apiFetch(`${API}/api/v3/quantum/stats`),
            apiFetch(`${API}/api/v3/process-type`),
            apiFetch(`${API}/api/v3/quantum/patterns`)
        ]);
        
        if (statsRes.ok) {
            const stats = await statsRes.json();
            const eMax = document.getElementById('qhEMax');
            const cMax = document.getElementById('qhCMax');
            const insights = document.getElementById('qhInsights');
            const missions = document.getElementById('qhMissions');
            const cycles = document.getElementById('qhTotalCycles');
            
            const eCount = stats.e_max_patterns ?? 0;
            const cCount = stats.c_max_patterns ?? 0;
            
            if (eMax) eMax.textContent = eCount;
            if (cMax) cMax.textContent = cCount;
            if (insights) insights.textContent = stats.failure_insights ?? 0;
            if (missions) missions.textContent = stats.active_missions ?? 0;
            if (cycles) cycles.textContent = stats.total_cycles ?? 0;
            
            // Update E-Max / C-Max ratio bar
            const total = eCount + cCount;
            const eMaxBar = document.getElementById('qhEMaxBar');
            const cMaxBar = document.getElementById('qhCMaxBar');
            if (eMaxBar && cMaxBar) {
                const ePct = total > 0 ? (eCount / total * 100) : 50;
                const cPct = total > 0 ? (cCount / total * 100) : 50;
                eMaxBar.style.width = `${ePct}%`;
                cMaxBar.style.width = `${cPct}%`;
            }
        }

        if (typeRes.ok) {
            const data = await typeRes.json();
            const modeEl = document.getElementById('qhCurrentMode');
            const pulseEl = document.getElementById('qhModePulse');
            if (modeEl) modeEl.textContent = data.process_type || 'Fleet';
            if (pulseEl) {
                const mode = (data.process_type || 'Fleet').toLowerCase();
                pulseEl.style.background = mode === 'quantum' ? 'var(--primary-400)' 
                    : mode === 'auto' ? 'var(--accent-gold)' 
                    : 'var(--accent-green)';
            }
            updateProcessTypeButtons(data.process_type || 'Fleet');
        }

        // V3: Render Pattern Vault (P7-11)
        if (patternsRes && patternsRes.ok) {
            const data = await patternsRes.json();
            renderPatternVault(data);
        }
    } catch (e) {
        console.warn('[V3] Quantum stats fetch failed:', e);
    }
}

function renderPatternVault(data) {
    // E-Max pattern list
    const emaxList = document.getElementById('emaxPatternList');
    const emaxCount = document.getElementById('qhEMaxCount');
    const emaxAvg = document.getElementById('qhEMaxAvg');
    if (emaxList && data.e_max) {
        if (emaxCount) emaxCount.textContent = data.e_max.length;
        if (data.e_max.length === 0) {
            emaxList.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:10px;">No efficiency patterns recorded yet</div>';
        } else {
            const avgRate = data.e_max.reduce((s, p) => s + p.success_rate, 0) / data.e_max.length;
            if (emaxAvg) emaxAvg.textContent = `avg ${(avgRate * 100).toFixed(0)}%`;
            emaxList.innerHTML = data.e_max.slice(0, 8).map(p => `
                <div style="display:flex; align-items:center; gap:8px; padding:6px 10px; background:var(--surface-800); border-radius:6px; border-left:2px solid var(--accent-green); font-size:11px;">
                    <i class="fa-solid fa-bolt" style="color:var(--accent-green); font-size:9px;"></i>
                    <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.name)}</span>
                    <span class="badge badge-green" style="font-size:9px; padding:1px 6px;">${(p.success_rate * 100).toFixed(0)}%</span>
                </div>
            `).join('');
        }
    }

    // C-Max pattern list
    const cmaxList = document.getElementById('cmaxPatternList');
    const cmaxCount = document.getElementById('qhCMaxCount');
    const cmaxAvg = document.getElementById('qhCMaxAvg');
    if (cmaxList && data.c_max) {
        if (cmaxCount) cmaxCount.textContent = data.c_max.length;
        if (data.c_max.length === 0) {
            cmaxList.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:10px;">No creative patterns discovered yet</div>';
        } else {
            const avgRate = data.c_max.reduce((s, p) => s + p.success_rate, 0) / data.c_max.length;
            if (cmaxAvg) cmaxAvg.textContent = `avg ${(avgRate * 100).toFixed(0)}%`;
            cmaxList.innerHTML = data.c_max.slice(0, 8).map(p => `
                <div style="display:flex; align-items:center; gap:8px; padding:6px 10px; background:var(--surface-800); border-radius:6px; border-left:2px solid var(--primary-400); font-size:11px;">
                    <i class="fa-solid fa-wand-magic-sparkles" style="color:var(--primary-400); font-size:9px;"></i>
                    <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.name)}</span>
                    <span class="badge" style="font-size:9px; padding:1px 6px; background:rgba(139,92,246,0.2); color:var(--primary-300);">${(p.success_rate * 100).toFixed(0)}%</span>
                </div>
            `).join('');
        }
    }

    // Failure Insights feed
    const insightsList = document.getElementById('failureInsightsList');
    const insightCount = document.getElementById('qhInsightCount');
    if (insightsList && data.insights) {
        if (insightCount) insightCount.textContent = data.insights.length;
        if (data.insights.length === 0) {
            insightsList.innerHTML = '<div style="color:var(--text-muted); font-size:12px; padding:10px; text-align:center;"><i class="fa-solid fa-seedling" style="margin-right:6px;"></i>Failures are seeds of innovation — insights will appear here</div>';
        } else {
            insightsList.innerHTML = data.insights.slice(0, 10).map(i => `
                <div style="padding:10px 12px; background:var(--surface-800); border-radius:8px; border-left:3px solid var(--accent-gold);">
                    <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:4px;">
                        <div style="font-size:11px; font-weight:600; color:var(--accent-gold);"><i class="fa-solid fa-lightbulb" style="margin-right:4px;"></i>${escapeHtml(i.failure.substring(0, 60))}${i.failure.length > 60 ? '...' : ''}</div>
                        <span style="font-size:9px; color:var(--text-muted); white-space:nowrap; margin-left:8px;">${i.created_at ? new Date(i.created_at).toLocaleDateString() : ''}</span>
                    </div>
                    <div style="font-size:10px; color:var(--text-secondary); line-height:1.4;">${escapeHtml(i.value.substring(0, 120))}${i.value.length > 120 ? '...' : ''}</div>
                    <div style="display:flex; gap:12px; margin-top:6px; font-size:9px; color:var(--text-muted);">
                        <span><i class="fa-solid fa-share-nodes" style="margin-right:3px;"></i>${i.diffusions} diffusions</span>
                        <span><i class="fa-solid fa-fire" style="margin-right:3px; color:${i.viral_score > 0.7 ? 'var(--accent-gold)' : 'var(--text-muted)'}"></i>viral: ${(i.viral_score * 100).toFixed(0)}%</span>
                    </div>
                </div>
            `).join('');
        }
    }
}

function updateProcessTypeButtons(activeType) {
    ['Fleet', 'Quantum', 'Auto'].forEach(type => {
        const btn = document.getElementById(`btn${type}`);
        if (!btn) return;
        if (type === activeType) {
            btn.style.background = 'var(--primary-600)';
            btn.style.color = 'white';
        } else {
            btn.style.background = 'var(--surface-700)';
            btn.style.color = 'var(--text-muted)';
        }
    });
}

window.setProcessType = async (type) => {
    try {
        const res = await apiFetch(`${API}/api/v3/process-type`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: type })
        });
        if (res.ok) {
            showToast(`Process type switched to ${type}`, "success");
            const modeEl = document.getElementById('qhCurrentMode');
            if (modeEl) modeEl.textContent = type;
            updateProcessTypeButtons(type);
        }
    } catch (e) {
        showToast("Failed to switch process type", "error");
    }
};


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
        if (missionEtaEl) missionEtaEl.textContent = m.status === 'Completed' || m.status === 'Success' ? 'All steps confirmed' : 'Autonomous execution active';
        
        const statusEl = document.getElementById('mcMissionStatus');
        if (statusEl) {
            statusEl.textContent = m.status;
            statusEl.className = 'badge ' + (m.status === 'Success' || m.status === 'Completed' ? 'badge-green' : 'badge-blue');
        }

        // Populate steps if containers/tags exist
        if (missionStepsContainer) {
            const description = m.description || (m.tasks && m.tasks.length > 0 ? m.tasks[0].desc : 'Executing autonomous task...');
            missionStepsContainer.innerHTML = `
                <div style="display:flex; align-items:center; gap:12px; padding:10px 12px; background:var(--surface-800); border-radius:8px; border-left:3px solid var(--primary-500);">
                    <span style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted); width:20px;">1</span>
                    <i class="fa-solid fa-brain" style="color:var(--primary-400); font-size:12px;"></i>
                    <span style="flex:1; font-size:13px;">${escapeHtml(description)}</span>
                    <span class="badge ${m.status === 'Success' || m.status === 'Completed' ? 'badge-green' : 'badge-blue'}" style="font-size:10px;">
                        ${m.status === 'InProgress' || m.status === 'Planning' ? '<i class="fa-solid fa-spinner fa-spin"></i> ' : ''}${m.status}
                    </span>
                </div>
            `;
        }
        
        // Timer Logic ⏱️
        if (m.started_at) {
            updateMissionTimer(m.started_at, m.completed_at);
        } else {
            const timerEl = document.getElementById('mcMissionTimer');
            if (timerEl) timerEl.textContent = '00:00:00';
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

function updateMissionTimer(startedAt, completedAt) {
    const el = document.getElementById('mcMissionTimer');
    if (!el) return;
    
    const start = new Date(startedAt).getTime();
    const end = completedAt ? new Date(completedAt).getTime() : Date.now();
    const diff = Math.max(0, end - start);
    
    const h = Math.floor(diff / 3600000);
    const m = Math.floor((diff % 3600000) / 60000);
    const s = Math.floor((diff % 60000) / 1000);
    
    el.textContent = `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
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
    if (logsEl) logsEl.textContent = status.log_count || '0';

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
    if (successEl) successEl.textContent = stats.success_rate ? `${stats.success_rate.toFixed(1)}%` : '--';
    if (timeEl) timeEl.textContent = stats.avg_time ? `${stats.avg_time.toFixed(1)}s` : '--';
    
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
                <button class="btn" style="padding:4px 8px; font-size:10px; border:none; background:var(--surface-700); color:var(--text-muted);" onclick="event.stopPropagation(); openEditAgentModal('${agent.id}')">
                    <i class="fa-solid fa-user-gear"></i>
                </button>
            </div>
        `;
    }).join('');
}

window.openEditAgentModal = async (agentId) => {
    try {
        const res = await apiFetch(`${API}/api/agents/${agentId}`);
        if (!res.ok) throw new Error("Failed to fetch agent profile");
        const data = await res.json();
        
        document.getElementById('eaAgentId').value = agentId;
        document.getElementById('eaName').value = data.name || '';
        document.getElementById('eaProfile').value = data.profile || 'Researcher';
        document.getElementById('eaPersona').value = data.identity?.persona || data.persona || '';
        
        document.getElementById('eaModalTitle').textContent = `Edit Persona: ${data.name}`;
        document.getElementById('editAgentModal').classList.add('open'); 
    } catch (e) {
        showToast("Failed to load agent: " + e.message, "error");
    }
};

window.closeEditAgentModal = () => {
    document.getElementById('editAgentModal').classList.remove('open');
};

window.saveAgentPersona = async () => {
    const id = document.getElementById('eaAgentId').value;
    const name = document.getElementById('eaName').value;
    const profile = document.getElementById('eaProfile').value;
    const persona = document.getElementById('eaPersona').value;

    // Build payload for identity update (device_name and display_name required)
    const payload = {
        device_name: name,
        display_name: name,
        avatar_url: '', // keep unchanged if not provided
        persona: persona,
        role: document.getElementById('eaRole')?.value || undefined,
        email: document.getElementById('eaEmail')?.value || undefined,
        messenger: document.getElementById('eaMessenger')?.value || undefined,
        phone: document.getElementById('eaPhone')?.value || undefined,
        language: document.getElementById('aiChatLangSelect')?.value || undefined,
    };

    const btn = document.getElementById('settingsIdentitySaveBtn');
    if (btn) btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

    try {
        const res = await apiFetch(`${API}/api/config/identity`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (res.ok) {
            showToast('Agent persona updated and persisted!', 'success');
            closeEditAgentModal();
            // Refresh agents list to reflect new persona
            if (typeof fetchAgents === 'function') fetchAgents();
        } else {
            const err = await res.json();
            showToast(`Failed to save persona: ${err.error || 'unknown'}`, 'error');
        }
    } catch (e) {
        showToast('Network error while saving persona.', 'error');
    } finally {
        if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i> Save';
    }
};

// ─── P7-09: Persona Agent Card ──────────────────────────────────

export async function fetchPersonaCard() {
    try {
        const res = await apiFetch(`${API}/api/v3/persona`);
        if (!res.ok) return;
        const data = await res.json();
        renderPersonaCard(data);
    } catch (e) {
        console.warn('[P7-09] Persona fetch failed:', e);
    }
}

function renderPersonaCard(data) {
    const avatarEl = document.getElementById('personaAvatar');
    const nameEl = document.getElementById('personaName');
    const styleEl = document.getElementById('personaStyle');
    const presetEl = document.getElementById('personaPresetBadge');

    if (avatarEl) avatarEl.textContent = data.avatar || '🤖';
    if (nameEl) nameEl.textContent = data.name || 'Agent';
    if (styleEl) styleEl.textContent = data.communication_style || '';
    if (presetEl) presetEl.textContent = data.preset || 'Custom';

    // Trait bars
    const traits = data.traits || {};
    const traitDefs = [
        { key: 'caution',   barId: 'traitCautionBar',   pctId: 'traitCautionPct' },
        { key: 'creativity', barId: 'traitCreativityBar', pctId: 'traitCreativityPct' },
        { key: 'autonomy',  barId: 'traitAutonomyBar',  pctId: 'traitAutonomyPct' },
        { key: 'verbosity', barId: 'traitVerbosityBar', pctId: 'traitVerbosityPct' },
    ];
    for (const t of traitDefs) {
        const val = traits[t.key] ?? 0.5;
        const pct = Math.round(val * 100);
        const barEl = document.getElementById(t.barId);
        const pctEl = document.getElementById(t.pctId);
        if (barEl) barEl.style.width = `${pct}%`;
        if (pctEl) pctEl.textContent = `${pct}%`;
    }

    // Specializations
    const specList = document.getElementById('personaSpecList');
    if (specList && data.specializations) {
        if (data.specializations.length === 0) {
            specList.innerHTML = '<span style="font-size:10px; color:var(--text-muted); padding:4px 8px;">No specializations yet</span>';
        } else {
            specList.innerHTML = data.specializations
                .sort((a, b) => b.confidence - a.confidence)
                .slice(0, 8)
                .map(s => {
                    const conf = Math.round(s.confidence * 100);
                    const color = conf >= 70 ? 'var(--accent-green)' : conf >= 40 ? 'var(--accent-gold)' : 'var(--text-muted)';
                    return `<span style="font-size:10px; padding:3px 8px; background:var(--surface-800); border-radius:6px; border:1px solid var(--surface-700); display:flex; align-items:center; gap:4px;">
                        <span style="width:5px; height:5px; border-radius:50%; background:${color}; flex-shrink:0;"></span>
                        ${escapeHtml(s.domain)} <span style="color:${color}; font-family:var(--font-mono); font-size:9px;">${conf}%</span>
                        <span style="color:var(--text-muted); font-size:8px;">(${s.completed_tasks}t/${s.lessons_applied}l)</span>
                    </span>`;
                })
                .join('');
        }
    }
}

// ─── P7-07: Quantum State Visualizer ────────────────────────────

export async function fetchQuantumStateVisualizer() {
    try {
        const res = await apiFetch(`${API}/api/v3/quantum/stats`);
        if (!res.ok) return;
        const stats = await res.json();
        renderQuantumStateVisualizer(stats);
    } catch (e) {
        console.warn('[P7-07] Quantum state fetch failed:', e);
    }
}

function renderQuantumStateVisualizer(stats) {
    const entropyEl = document.getElementById('qvEntropy');
    const qubitCountEl = document.getElementById('qvQubitCount');
    const entangledEl = document.getElementById('qvEntangled');
    const butterflyEl = document.getElementById('qvButterfly');

    // Approximate metrics from hub stats
    const totalPatterns = (stats.e_max_patterns ?? 0) + (stats.c_max_patterns ?? 0);
    const activeMissions = stats.active_missions ?? 0;
    const cycles = stats.total_cycles ?? 0;
    const insights = stats.failure_insights ?? 0;

    // Synthetic entropy: higher when more diverse patterns
    const entropy = totalPatterns > 0 ? Math.min(1.0, Math.log2(totalPatterns + 1) / 5).toFixed(2) : '0.00';
    // Estimated qubit count from active missions
    const qubitEstimate = activeMissions * 3 + totalPatterns;
    // Entanglement pairs estimate
    const entangledPairs = activeMissions > 0 ? activeMissions * 2 : 0;
    // Butterfly phase (gamma cycles)
    const butterflyPhase = cycles;

    if (entropyEl) entropyEl.textContent = entropy;
    if (qubitCountEl) qubitCountEl.textContent = qubitEstimate;
    if (entangledEl) entangledEl.textContent = entangledPairs;
    if (butterflyEl) butterflyEl.textContent = butterflyPhase;

    // Render qubit state bars (visual approximation)
    const container = document.getElementById('qubitStatesContainer');
    if (!container) return;

    if (totalPatterns === 0 && activeMissions === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:10px; text-align:center;"><i class="fa-solid fa-atom" style="margin-right:6px;"></i>No active quantum mission states</div>';
        return;
    }

    // Generate visual qubit bars from stats
    const bars = [];
    if (stats.e_max_patterns > 0) {
        bars.push({ label: 'E-Max Register', prob: 0.5 + Math.min(0.45, stats.e_max_patterns * 0.05), color: 'var(--accent-green)' });
    }
    if (stats.c_max_patterns > 0) {
        bars.push({ label: 'C-Max Register', prob: 0.5 + Math.min(0.45, stats.c_max_patterns * 0.05), color: 'var(--primary-400)' });
    }
    if (insights > 0) {
        bars.push({ label: 'Insight Register', prob: 0.3 + Math.min(0.5, insights * 0.07), color: 'var(--accent-gold)' });
    }
    if (activeMissions > 0) {
        bars.push({ label: `Mission (${activeMissions})`, prob: 0.6 + Math.min(0.3, activeMissions * 0.1), color: 'var(--accent-cyan, #22d3ee)' });
    }

    if (bars.length === 0) {
        bars.push({ label: 'System Idle', prob: 0.5, color: 'var(--text-muted)' });
    }

    container.innerHTML = bars.map(b => {
        const pct = Math.round(b.prob * 100);
        return `<div style="display:flex; align-items:center; gap:8px; padding:5px 10px; background:var(--surface-800); border-radius:6px; font-size:10px;">
            <span style="width:4px; height:4px; border-radius:50%; background:${b.color}; flex-shrink:0;"></span>
            <span style="flex:1; color:var(--text-secondary); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">|ψ⟩ ${escapeHtml(b.label)}</span>
            <div style="width:80px; height:3px; background:var(--surface-700); border-radius:2px; overflow:hidden;">
                <div style="width:${pct}%; height:100%; background:${b.color}; border-radius:2px; transition:width 0.5s ease;"></div>
            </div>
            <span style="font-family:var(--font-mono); color:${b.color}; min-width:28px; text-align:right;">${pct}%</span>
        </div>`;
    }).join('');
}

// ─── P7-10: Automation Scheduler UI ─────────────────────────────

export async function fetchSchedulerJobs() {
    try {
        const res = await apiFetch(`${API}/api/v3/scheduler/jobs`);
        if (!res.ok) return;
        const data = await res.json();
        renderSchedulerJobs(data.jobs || []);
    } catch (e) {
        console.warn('[P7-10] Scheduler fetch failed:', e);
    }
}

function renderSchedulerJobs(jobs) {
    const container = document.getElementById('schedulerJobList');
    const countEl = document.getElementById('schedulerJobCount');
    if (countEl) countEl.textContent = `${jobs.length} job${jobs.length !== 1 ? 's' : ''}`;
    if (!container) return;

    if (jobs.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:10px; text-align:center;"><i class="fa-solid fa-clock" style="margin-right:6px;"></i>No scheduled jobs — create one to automate workflows</div>';
        return;
    }

    container.innerHTML = jobs.map(j => {
        const enabledColor = j.enabled ? 'var(--accent-green)' : 'var(--text-muted)';
        const statusIcon = j.enabled ? 'fa-circle-play' : 'fa-circle-pause';
        return `<div style="display:flex; align-items:center; gap:8px; padding:8px 10px; background:var(--surface-800); border-radius:6px; border-left:2px solid ${enabledColor}; font-size:11px;">
            <i class="fa-solid ${statusIcon}" style="color:${enabledColor}; cursor:pointer; font-size:12px;" onclick="toggleSchedulerJob('${j.id}', ${!j.enabled})"></i>
            <div style="flex:1; min-width:0;">
                <div style="font-weight:600; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(j.name)}</div>
                <div style="font-size:9px; color:var(--text-muted); font-family:var(--font-mono);">${escapeHtml(j.cron_expr)} → ${escapeHtml(j.template_id)}</div>
            </div>
            <span style="font-family:var(--font-mono); font-size:9px; color:var(--text-muted);">${j.run_count}x</span>
            <i class="fa-solid fa-trash" style="color:var(--text-muted); cursor:pointer; font-size:10px; opacity:0.6;" onclick="deleteSchedulerJob('${j.id}')" onmouseover="this.style.opacity='1';this.style.color='var(--accent-red, #ef4444)'" onmouseout="this.style.opacity='0.6';this.style.color='var(--text-muted)'"></i>
        </div>`;
    }).join('');
}

window.openSchedulerModal = () => {
    const modal = document.getElementById('schedulerModal');
    if (modal) modal.style.display = 'flex';
};

window.closeSchedulerModal = () => {
    const modal = document.getElementById('schedulerModal');
    if (modal) modal.style.display = 'none';
};

window.submitSchedulerJob = async () => {
    const name = document.getElementById('schedName')?.value?.trim();
    const cron = document.getElementById('schedCron')?.value?.trim();
    const template = document.getElementById('schedTemplate')?.value?.trim();
    if (!name || !cron || !template) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    try {
        const res = await apiFetch(`${API}/api/v3/scheduler/jobs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, cron_expr: cron, template_id: template })
        });
        if (res.ok) {
            showToast(`Scheduled job "${name}" created`, 'success');
            closeSchedulerModal();
            fetchSchedulerJobs();
        } else {
            const err = await res.json();
            showToast(`Failed: ${err.error || 'unknown'}`, 'error');
        }
    } catch (e) {
        showToast('Network error creating job', 'error');
    }
};

window.toggleSchedulerJob = async (jobId, enabled) => {
    try {
        await apiFetch(`${API}/api/v3/scheduler/jobs/${jobId}/toggle`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        fetchSchedulerJobs();
    } catch (e) {}
};

window.deleteSchedulerJob = async (jobId) => {
    try {
        await apiFetch(`${API}/api/v3/scheduler/jobs/${jobId}`, { method: 'DELETE' });
        showToast('Job removed', 'success');
        fetchSchedulerJobs();
    } catch (e) {}
};

// ─── P5: Governance Dashboard UI ────────────────────────────────

export async function fetchGovernanceDashboard() {
    try {
        const res = await apiFetch(`${API}/api/v3/governance/proposals`);
        if (!res.ok) return;
        const data = await res.json();
        renderGovernanceDashboard(data);
    } catch (e) {
        console.warn('[P5] Governance fetch failed:', e);
    }
}

function renderGovernanceDashboard(data) {
    const proposals = data.proposals || [];
    const stats = data.stats || {};

    // Stats
    const openEl = document.getElementById('govOpen');
    const approvedEl = document.getElementById('govApproved');
    const rejectedEl = document.getElementById('govRejected');
    const chainEl = document.getElementById('govChain');
    const participEl = document.getElementById('govParticipation');

    if (openEl) openEl.textContent = stats.open ?? proposals.filter(p => p.state === 'Open').length;
    if (approvedEl) approvedEl.textContent = stats.approved ?? proposals.filter(p => p.state === 'Approved').length;
    if (rejectedEl) rejectedEl.textContent = stats.rejected ?? proposals.filter(p => p.state === 'Rejected').length;
    if (chainEl) chainEl.textContent = stats.chain_length ?? 0;
    if (participEl) participEl.textContent = stats.avg_participation ? `${(stats.avg_participation * 100).toFixed(0)}%` : '--';

    // Proposal list
    const container = document.getElementById('governanceProposalList');
    if (!container) return;

    if (proposals.length === 0) {
        container.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:10px; text-align:center;"><i class="fa-solid fa-shield-halved" style="margin-right:6px;"></i>No governance proposals</div>';
        return;
    }

    container.innerHTML = proposals.slice(0, 6).map(p => {
        const stateColor = p.state === 'Open' ? 'var(--accent-gold)' : p.state === 'Approved' ? 'var(--accent-green)' : 'var(--accent-red, #ef4444)';
        const sevIcon = p.severity === 'Critical' ? 'fa-circle-exclamation' : p.severity === 'High' ? 'fa-triangle-exclamation' : 'fa-circle-info';
        return `<div style="padding:8px 10px; background:var(--surface-800); border-radius:6px; border-left:2px solid ${stateColor}; font-size:11px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-weight:600;"><i class="fa-solid ${sevIcon}" style="color:${stateColor}; margin-right:4px; font-size:9px;"></i>${escapeHtml(p.title || 'Untitled')}</span>
                <span style="font-size:9px; padding:1px 6px; border-radius:4px; background:rgba(255,255,255,0.05); color:${stateColor};">${p.state}</span>
            </div>
            <div style="font-size:9px; color:var(--text-muted); margin-top:3px; display:flex; gap:10px;">
                <span><i class="fa-solid fa-check" style="margin-right:2px;"></i>${p.votes_for ?? 0} for</span>
                <span><i class="fa-solid fa-xmark" style="margin-right:2px;"></i>${p.votes_against ?? 0} against</span>
                <span>${escapeHtml(p.proposer || 'system')}</span>
            </div>
        </div>`;
    }).join('');
}

window.openGovernanceModal = () => {
    const modal = document.getElementById('governanceModal');
    if (modal) modal.style.display = 'flex';
};

window.closeGovernanceModal = () => {
    const modal = document.getElementById('governanceModal');
    if (modal) modal.style.display = 'none';
};

window.submitGovernanceProposal = async () => {
    const title = document.getElementById('govTitle')?.value?.trim();
    const description = document.getElementById('govDescription')?.value?.trim();
    const severity = document.getElementById('govSeverity')?.value || 'low';
    if (!title || !description) {
        showToast('Please fill in title and description', 'error');
        return;
    }
    try {
        const res = await apiFetch(`${API}/api/v3/governance/proposals`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, description, severity })
        });
        if (res.ok) {
            showToast(`Proposal "${title}" submitted`, 'success');
            closeGovernanceModal();
            fetchGovernanceDashboard();
        } else {
            const err = await res.json();
            showToast(`Failed: ${err.error || 'unknown'}`, 'error');
        }
    } catch (e) {
        showToast('Network error submitting proposal', 'error');
    }
};

// ─── P3-08: Viral Diffusion Live Feed ───────────────────────────

export async function fetchDiffusionStats() {
    try {
        const res = await apiFetch(`${API}/api/v3/diffusion/stats`);
        if (!res.ok) return;
        const stats = await res.json();
        renderDiffusionStats(stats);
    } catch (e) {
        console.warn('[P3-08] Diffusion stats fetch failed:', e);
    }
}

function renderDiffusionStats(stats) {
    const activeEl = document.getElementById('diffusionActiveCount');
    const createdEl = document.getElementById('diffCreated');
    const totalEl = document.getElementById('diffTotal');
    const avgEl = document.getElementById('diffAvgViral');

    if (activeEl) activeEl.textContent = stats.active_packets ?? 0;
    if (createdEl) createdEl.textContent = stats.total_created ?? 0;
    if (totalEl) totalEl.textContent = stats.total_diffusions ?? 0;
    if (avgEl) avgEl.textContent = stats.avg_viral_score != null ? `${(stats.avg_viral_score * 100).toFixed(0)}%` : '--';

    // Top viral packets
    fetchDiffusionTop();
}

async function fetchDiffusionTop() {
    try {
        const res = await apiFetch(`${API}/api/v3/diffusion/top`);
        if (!res.ok) return;
        const data = await res.json();
        const container = document.getElementById('diffusionTopList');
        if (!container) return;
        const packets = data.packets || [];

        if (packets.length === 0) {
            container.innerHTML = '<div style="color:var(--text-muted); font-size:11px; padding:8px; text-align:center;">No diffusion packets yet</div>';
            return;
        }

        container.innerHTML = packets.slice(0, 5).map(p => {
            const typeIcon = p.packet_type === 'Warning' ? 'fa-triangle-exclamation' : p.packet_type === 'Innovation' ? 'fa-wand-magic-sparkles' : p.packet_type === 'FailureInsight' ? 'fa-lightbulb' : 'fa-bolt';
            const typeColor = p.packet_type === 'Warning' ? 'var(--accent-red, #ef4444)' : p.packet_type === 'Innovation' ? 'var(--primary-400)' : p.packet_type === 'FailureInsight' ? 'var(--accent-gold)' : 'var(--accent-green)';
            return `<div style="display:flex; align-items:center; gap:6px; padding:5px 8px; background:var(--surface-800); border-radius:5px; font-size:10px;">
                <i class="fa-solid ${typeIcon}" style="color:${typeColor}; font-size:9px;"></i>
                <span style="flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">${escapeHtml(p.content?.substring(0, 60) || '')}</span>
                <span style="font-family:var(--font-mono); color:var(--accent-pink, #ec4899); font-size:9px;">${(p.viral_score * 100).toFixed(0)}%</span>
            </div>`;
        }).join('');
    } catch (e) {}
}

// ─── P1-12: Communication Hub Stats ─────────────────────────────

export async function fetchCommHubStats() {
    try {
        const res = await apiFetch(`${API}/api/v3/comm/stats`);
        if (!res.ok) return;
        const stats = await res.json();
        const agentsEl = document.getElementById('commAgents');
        const messagesEl = document.getElementById('commMessages');
        const unreadEl = document.getElementById('commUnread');
        if (agentsEl) agentsEl.textContent = stats.registered_agents ?? 0;
        if (messagesEl) messagesEl.textContent = stats.total_messages ?? 0;
        if (unreadEl) unreadEl.textContent = stats.total_unread ?? 0;
    } catch (e) {
        console.warn('[P1-12] CommHub stats fetch failed:', e);
    }
}
