import { API, apiFetch, showToast, setTranslatedText } from './core.js';

export let currentMarketCategory = 'processes';

export function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function normalizeAgentStatus(status) {
    return String(status || 'offline').toLowerCase();
}

function normalizeCapabilities(caps) {
    if (!caps) return [];
    if (Array.isArray(caps)) return caps.map(String);
    if (typeof caps === 'string') {
        try {
            const parsed = JSON.parse(caps);
            return Array.isArray(parsed) ? parsed.map(String) : [caps];
        } catch (_) {
            return caps.split(',').map(s => s.trim()).filter(Boolean);
        }
    }
    return [];
}

function extractAgentList(data) {
    if (Array.isArray(data)) return data;
    if (data && typeof data === 'object') {
        if (Array.isArray(data.agents)) return data.agents;
        if (Array.isArray(data.entries)) return data.entries;
        if (Array.isArray(data.list)) return data.list;
    }
    return [];
}

export async function fetchMarketplaceAgents() {
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
    
    if (typeof window.updateMarketStats === 'function') window.updateMarketStats();
    renderMarketGraph();
}

let marketGraphAnimation = null;
export function renderMarketGraph() {
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

export function switchMarketTab(btn, mode) {
    document.querySelectorAll('#view-market .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentMarketCategory = mode;
    fetchMarketplaceAgents();
}

export async function hireAgent(agentId, agentName, selectedAgentId = 'local') {
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
        if (window.fetchTasks) window.fetchTasks();
    } catch (e) {
        showToast(`Hire failed: ${e?.message || 'unknown error'}`, 'error');
    }
}

let deployTargetAgentId = null;

export function deployAgent(agentId, agentName) {
    deployTargetAgentId = agentId;
    const title = document.getElementById('deployAgentTitle');
    if (title) title.textContent = agentName || agentId;
    document.getElementById('agentDeployModal')?.classList.add('open');
}

export async function confirmDeploy() {
    if (!deployTargetAgentId) return;
    const target    = document.getElementById('deployTarget')?.value || 'local';
    const role      = document.getElementById('deployRole')?.value || 'worker';
    const autoStart = document.getElementById('deployAutoStart')?.value === 'yes';
    const notes     = document.getElementById('deployNotes')?.value?.trim() || '';

    showToast(`Deploying ${deployTargetAgentId} to ${target} as ${role}...`, 'info');
    document.getElementById('agentDeployModal')?.classList.remove('open');

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
            showToast('Deploy failed - check agent connectivity', 'error');
        }
    } catch(e) {
        showToast('Deploy request failed', 'error');
    }
}

export async function installAgent(agentId, agentName) {
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

export async function inspectAgentModal(agentId) {
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

export async function loadRentPolicy() {
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

export async function submitRentPolicy() {
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
        document.getElementById('rentPolicyModal').style.display = 'none';
    } catch (e) {
        showToast(`Save failed: ${e?.message || 'unknown error'}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-check"></i> Save Policy';
        }
    }
}
