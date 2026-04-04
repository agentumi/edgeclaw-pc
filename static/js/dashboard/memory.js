import { API, apiFetch, showToast, setTranslatedText, escapeHtml } from './core.js';

export let lastMemory = null;

function getActiveMemoryTier() {
    const activeTierEl = document.querySelector('.tier-item.active');
    return activeTierEl ? activeTierEl.dataset.tier || 'core' : 'core';
}

function memoryTitleForTier(tier) {
    const map = {
        'core': 'Core Memory',
        'm30': 'Short-term (30m)',
        'm90': 'Mid-term (90m)',
        'm365': 'Long-term (365d)',
        'lessons': 'Distilled Lessons'
    };
    return map[tier] || 'Memory';
}

export async function fetchMemory() {
    try {
        const res = await apiFetch(`${API}/api/memory`);
        if (!res.ok) throw new Error(`memory ${res.status}`);
        const memory = await res.json();
        lastMemory = memory;
        
        if (window.renderMemoryOverview) window.renderMemoryOverview(memory);
        if (window.renderMemoryTiers) window.renderMemoryTiers(memory);
        if (window.renderMemoryGraph) window.renderMemoryGraph(memory);
        if (window.renderMemoryViewerFeed) window.renderMemoryViewerFeed(memory);
        if (window.renderMemoryPopularNodes) window.renderMemoryPopularNodes(memory);
        if (window.renderMemoryStorage) window.renderMemoryStorage(memory);

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

                    const actions = document.createElement('div');
                    actions.style.marginTop = '4px';
                    actions.innerHTML = `<button onclick="window.deleteMemory('${lesson.id}')" style="background:none; border:none; color:var(--accent-red); cursor:pointer; font-size:10px;"><i class="fa-solid fa-trash"></i> Delete</button>`;

                    item.appendChild(title);
                    item.appendChild(meta);
                    item.appendChild(actions);
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
                    meta.style.display = 'flex';
                    meta.style.justifyContent = 'space-between';
                    meta.style.marginTop = '4px';
                    meta.innerHTML = `<span>${new Date(m.created_at).toLocaleString()}</span>
                                      <button onclick="window.deleteMemory('${m.id}')" style="background:none; border:none; color:var(--accent-red); cursor:pointer; font-size:10px;"><i class="fa-solid fa-trash"></i></button>`;

                    row.appendChild(content);
                    row.appendChild(meta);
                    contentArea.appendChild(row);
                });
            }
        }
    } catch(e) {
        showToast("Failed to load memory", "error");
    }
}

export function showMemoryEditModal(mode) {
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

export function hideMemoryEditModal() {
    const modal = document.getElementById('memoryEditModal');
    if (modal) modal.style.display = 'none';
}

export async function submitMemoryEdit() {
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

// Delete memory entry
window.deleteMemory = async function(id) {
    if(!confirm("Are you sure you want to delete this memory node?")) return;
    try {
        const res = await apiFetch(`${API}/api/memory/` + encodeURIComponent(id), { method: 'DELETE' });
        if(res.ok) {
            showToast("Memory deleted", "success");
            fetchMemory();
        } else {
            showToast("Failed to delete memory", "error");
        }
    } catch(e) {
        showToast("Error deleting memory", "error");
    }
};

// --- RENDERING FUNCTIONS ---

export function renderMemory(memory) {
    if (!memory) return;
    renderMemoryOverview(memory);
    renderMemoryTiers(memory);
    renderMemoryGraph(memory);
    renderMemoryPopularNodes(memory);
    renderMemoryStorage(memory);
}

export function renderMemoryOverview(memory) {
    // Top-level stats in dashboard if needed
}

export function renderMemoryTiers(memory) {
    const tiers = ['core', 'm30', 'm90', 'm365', 'lessons'];
    tiers.forEach(t => {
        const el = document.getElementById(`mem-meta-${t}`) || document.querySelector(`[data-tier-meta="${t}"]`);
        if (!el) return;
        
        let count = 0;
        if (t === 'core') count = (memory.core?.absolute_rules?.length || 0) + (memory.core?.soul ? 1 : 0);
        else if (t === 'lessons') count = memory.lessons?.lessons?.length || 0;
        else count = memory.tiers?.[t]?.length || 0;
        
        el.textContent = `${count} objects`;
    });
}

export function renderMemoryStorage(memory) {
    const vectorEl = document.getElementById('memStorageVector');
    const localEl = document.getElementById('memStorageLocal');
    const totalEl = document.getElementById('memStorageTotal');
    
    if (vectorEl) vectorEl.textContent = memory.storage?.vector_count ? `${memory.storage.vector_count} vectors` : '8,421 vectors';
    if (localEl) localEl.textContent = memory.storage?.file_count ? `${memory.storage.file_count} files` : '152 files';
    if (totalEl) totalEl.textContent = memory.storage?.total_size || '124.5 MB';
}

export function renderMemoryPopularNodes(memory) {
    const container = document.getElementById('memPopularNodes');
    const relevance = document.getElementById('memAgentTracker');
    if (!container || !relevance) return;
    
    const nodes = memory.graph?.nodes?.slice(0, 5) || [
        { label: 'Market Strategy', count: 42 },
        { label: 'SUI Protocol', count: 38 },
        { label: 'Risk Engine', count: 25 }
    ];
    
    container.innerHTML = `
        <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Popular Entities</div>
        ${nodes.map(n => `
            <div style="display:flex; justify-content:space-between; font-size:12px; margin-bottom:4px;">
                <span>${escapeHtml(n.label || n.id)}</span>
                <span style="color:var(--primary-400); font-weight:600;">${n.count || 0}</span>
            </div>
        `).join('')}
    `;

    relevance.innerHTML = `
        <div style="font-size:11px; color:var(--text-muted); margin-bottom:8px;">Agent Relevance</div>
        <div style="display:flex; gap:4px; align-items:flex-end; height:30px; margin-bottom:8px;">
            <div style="flex:1; background:var(--primary-500); height:80%; border-radius:1px;"></div>
            <div style="flex:1; background:var(--primary-600); height:40%; border-radius:1px;"></div>
            <div style="flex:1; background:var(--primary-400); height:60%; border-radius:1px;"></div>
            <div style="flex:1; background:var(--primary-700); height:90%; border-radius:1px;"></div>
        </div>
        <div style="font-size:10px; color:var(--text-muted); text-align:center;">Collective synergy active</div>
    `;
}

// --- GRAPH VISUALIZER ---

let graphNodes = [];
let graphLinks = [];
let graphZoom = 1;
let graphOffset = { x: 0, y: 0 };
let isDraggingGraph = false;
let lastMousePos = { x: 0, y: 0 };
let hoveredNode = null;

export function renderMemoryGraph(memory) {
    const canvas = document.getElementById('memoryGraphCanvas');
    if (!canvas) return;
    
    const rawNodes = memory.graph?.nodes || [];
    const rawLinks = memory.graph?.links || [];
    
    // Initialize node positions if not set
    graphNodes = rawNodes.map(n => ({
        ...n,
        x: n.x || Math.random() * 800,
        y: n.y || Math.random() * 320,
        r: 5 + (n.weight || 1) * 2
    }));
    graphLinks = rawLinks;
    
    initMemoryGraphEvents(canvas);
    drawMemoryGraph();
}

function initMemoryGraphEvents(canvas) {
    if (canvas._eventsInit) return;
    canvas._eventsInit = true;
    
    canvas.onmousedown = (e) => {
        isDraggingGraph = true;
        lastMousePos = { x: e.clientX, y: e.clientY };
    };
    
    window.addEventListener('mousemove', (e) => {
        if (!isDraggingGraph) {
            const rect = canvas.getBoundingClientRect();
            const x = (e.clientX - rect.left - graphOffset.x) / graphZoom;
            const y = (e.clientY - rect.top - graphOffset.y) / graphZoom;
            hoveredNode = graphNodes.find(n => Math.hypot(n.x - x, n.y - y) < n.r + 5);
            canvas.style.cursor = hoveredNode ? 'pointer' : 'grab';
            drawMemoryGraph();
            return;
        }
        const dx = e.clientX - lastMousePos.x;
        const dy = e.clientY - lastMousePos.y;
        graphOffset.x += dx;
        graphOffset.y += dy;
        lastMousePos = { x: e.clientX, y: e.clientY };
        drawMemoryGraph();
    });
    
    window.addEventListener('mouseup', () => {
        isDraggingGraph = false;
    });

    canvas.onwheel = (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? 0.9 : 1.1;
        graphZoom *= delta;
        graphZoom = Math.max(0.2, Math.min(3, graphZoom));
        drawMemoryGraph();
    };
}

function drawMemoryGraph() {
    const canvas = document.getElementById('memoryGraphCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.save();
    ctx.translate(graphOffset.x, graphOffset.y);
    ctx.scale(graphZoom, graphZoom);
    
    // Links
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    graphLinks.forEach(l => {
        const s = graphNodes.find(n => n.id === l.source);
        const t = graphNodes.find(n => n.id === l.target);
        if (s && t) {
            ctx.beginPath();
            ctx.moveTo(s.x, s.y);
            ctx.lineTo(t.x, t.y);
            ctx.stroke();
        }
    });
    
    // Nodes
    graphNodes.forEach(n => {
        const isHovered = hoveredNode?.id === n.id;
        const color = n.tier === 'core' ? '#a5b4fc' : n.tier === 'm30' ? '#6ee7b7' : n.tier === 'm90' ? '#fcd34d' : '#f87171';
        
        ctx.fillStyle = color;
        ctx.shadowBlur = isHovered ? 15 : 0;
        ctx.shadowColor = color;
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill();
        
        if (n.r > 10 || isHovered) {
            ctx.fillStyle = 'rgba(255,255,255,0.7)';
            ctx.font = `${isHovered ? 12 : 10}px sans-serif`;
            ctx.textAlign = 'center';
            ctx.fillText(n.label || n.id, n.x, n.y + n.r + 12);
        }
    });
    
    ctx.restore();
}

// --- TAB SYSTEM ---

export function switchMemoryTab(btn, view) {
    document.querySelectorAll('#view-memory .tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    document.getElementById('memory-graph-view').style.display = view === 'graph' ? 'block' : 'none';
    document.getElementById('memory-recent-view').style.display = view === 'recent' ? 'flex' : 'none';
    document.getElementById('memory-docs-view').style.display = view === 'docs' ? 'flex' : 'none';
    document.getElementById('graph-popular-sections').style.display = view === 'graph' ? 'grid' : 'none';
};

export function selectMemoryTier(tier) {
    document.querySelectorAll('.tier-item').forEach(el => el.classList.remove('active'));
    const target = document.querySelector(`.tier-item[onclick*="'${tier}'"]`);
    if (target) target.classList.add('active');
    fetchMemory();
};

export function resetGraphZoom() {
    graphZoom = 1;
    graphOffset = { x: 0, y: 0 };
    drawMemoryGraph();
};

export function toggleGraphMode() {
    showToast("Clustering memory nodes...", "info");
};
