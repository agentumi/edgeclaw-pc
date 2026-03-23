import { API, apiFetch, showToast, escapeHtml } from './core.js';

export let agentGraphNodes = [];
export let agentGraphLinks = [];
export let selectedAgentNode = null;
export let agentGraphHover = null;
export let agentGraphDraggingNode = null;

function normalizeAgentStatus(status) {
    return String(status || 'offline').toLowerCase();
}

export function fetchAgentGraph(cachedAgents) {
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
    updateAgentFleetStrip(cachedAgents);
}

export function renderAgentGraph() {
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
            if (window.inspectAgent) window.inspectAgent(selectedAgentNode.id);
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
            inspectAgentBoard(selectedAgentNode.id, window.cachedAgents);
        }
    };

    draw();
}

export function updateAgentFleetStrip(cachedAgents) {
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

export async function inspectAgentBoard(agentId, cachedAgents) {
    const agent = cachedAgents?.find(a => a.id === agentId);
    if (!agent) return;
    
    // Update Header
    const nameEl = document.getElementById('agentDetailName');
    const dotEl = document.getElementById('agentDetailStatusDot');
    if (nameEl) nameEl.textContent = agent.name;
    if (dotEl) {
        const online = normalizeAgentStatus(agent.status) === 'online';
        dotEl.className = `status-dot ${online ? 'online' : 'away'}`;
    }

    // Update Identity Card
    const metaEl = document.getElementById('agentDetailMeta');
    const statusEl = document.getElementById('agentDetailStatus');
    const profileEl = document.getElementById('agentDetailProfile');
    const reputationEl = document.getElementById('agentDetailReputation');

    if (metaEl) metaEl.textContent = `ID: ${agent.id.slice(0, 12)}... (${agent.address}:${agent.port})`;
    if (statusEl) {
        const online = normalizeAgentStatus(agent.status) === 'online';
        statusEl.textContent = online ? 'Online' : 'Away';
        statusEl.className = `badge ${online ? 'badge-green' : 'badge-gold'}`;
    }
    if (profileEl) {
        profileEl.textContent = agent.profile || 'Worker';
        profileEl.className = `badge ${agent.profile === 'Orchestrator' ? 'badge-purple' : 'badge-blue'}`;
    }
    if (reputationEl) {
        reputationEl.textContent = agent.performance_rating ? agent.performance_rating.toFixed(1) : '5.0';
    }

    if (window.loadAgentProfileDetails) await window.loadAgentProfileDetails(agentId, agent);
    
    // Highlight in graph if not already
    selectedAgentNode = agentGraphNodes.find(n => n.id === agentId);
    renderAgentGraph();
    updateAgentFleetStrip(cachedAgents);
}

export function showAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'flex';
}

export function hideAddAgentModal() {
    document.getElementById('addAgentModal').style.display = 'none';
    document.getElementById('newAgentName').value = '';
}

export async function submitAddAgent() {
    const name = document.getElementById('newAgentName').value.trim();
    const addr = document.getElementById('newAgentAddr').value.trim();
    const portArr = document.getElementById('newAgentPort');
    const port = portArr ? parseInt(portArr.value) : 2200;

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
            if (window.refreshAgentsUI) window.refreshAgentsUI();
            if (window.fetchMarketplaceAgents) window.fetchMarketplaceAgents();
        }
    } catch(e) {
        showToast("Failed to register agent", "error");
    }
}

export async function discoverAgents() {
    const btn = document.getElementById('discoverBtn');
    const originalHtml = btn ? btn.innerHTML : '';
    if (btn) {
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';
        btn.disabled = true;
    }

    try {
        const res = await apiFetch(`${API}/api/agents/discover`, { method: 'POST' });
        if (res.ok) {
            const found = await res.json();
            showToast(`Scan complete. Found ${found.length} agents.`, "success");
            if (window.refreshAgentsUI) window.refreshAgentsUI();
            if (window.fetchMarketplaceAgents) window.fetchMarketplaceAgents();
        }
    } catch(e) {
        showToast("Discovery failed", "error");
    } finally {
        if (btn) {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    }
}
export function toggleAgentViewTab(btn, mode) {
    if (!btn) return;
    
    // Update button states
    const tabs = btn.parentElement.querySelectorAll('.tab-btn');
    tabs.forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    
    // Toggle areas
    const areas = ['graph', 'list', 'kanban'];
    areas.forEach(a => {
        const el = document.getElementById(`agent-${a}-area`);
        if (el) el.style.display = (a === mode) ? 'block' : 'none';
    });
    
    if (mode === 'graph') {
        renderAgentGraph();
    } else if (mode === 'list') {
        renderAgentList();
    }
}

function renderAgentList() {
    const tbody = document.getElementById('agent-list-table-body');
    if (!tbody) return;
    
    if (agentGraphNodes.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="padding:40px; text-align:center; color:var(--text-muted);">No agents found</td></tr>';
        return;
    }
    
    tbody.innerHTML = agentGraphNodes.map(n => `
        <tr style="border-bottom:1px solid var(--surface-700);">
            <td style="padding:16px; display:flex; align-items:center; gap:12px;">
                <div style="width:32px; height:32px; border-radius:8px; background:var(--surface-700); display:flex; align-items:center; justify-content:center; color:var(--primary-400);">
                    <i class="fa-solid fa-robot"></i>
                </div>
                <div>
                    <div style="font-weight:600;">${escapeHtml(n.name)}</div>
                    <div style="font-size:10px; color:var(--text-muted);">${n.id.slice(0, 12)}</div>
                </div>
            </td>
            <td style="padding:16px;">
                <span class="badge ${n.status === 'online' ? 'badge-green' : 'badge-gold'}">${n.status}</span>
            </td>
            <td style="padding:16px; font-family:var(--font-mono); font-size:11px;">${n.address || '127.0.0.1'}:${n.port || '8443'}</td>
            <td style="padding:16px;"><span class="badge badge-blue">Worker</span></td>
            <td style="padding:16px; text-align:right;">
                <button class="ec-icon-btn" onclick="inspectAgentBoard('${n.id}')"><i class="fa-solid fa-eye"></i></button>
                <button class="ec-icon-btn" style="color:var(--accent-red)"><i class="fa-solid fa-trash-can"></i></button>
            </td>
        </tr>
    `).join('');
}
