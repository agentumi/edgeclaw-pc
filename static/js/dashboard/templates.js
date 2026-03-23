import { API, AppState, apiFetch, showToast, escapeHtml } from './core.js';

let templateData = [];
let currentTemplateCategory = 'all';
let currentTemplateId = null;

export function setTemplateData(templates) {
    templateData = templates;
}

export const getCatKey = (t) => {
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

export async function fetchTemplates() {
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

export function renderTemplates() {
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
            marketing: { name: 'Marketing', icon: '📈', color: '#f59e0b', templates: [] },
            security: { name: 'Security', icon: '🛡️', color: '#ef4444', templates: [] },
            system: { name: 'System', icon: '🖥️', color: '#64748b', templates: [] }
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
        if (btn.textContent) {
            const baseText = btn.textContent.split(' (')[0];
            btn.textContent = `${baseText} (${count})`;
        }
        btn.classList.toggle('active', cat === currentTemplateCategory);
    });
}

export function renderTemplateCard(t) {
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

export function filterTemplates(category) {
    currentTemplateCategory = category;
    
    // Update tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.category === category);
    });
    
    renderTemplates();
}

export function searchTemplates(query) {
    renderTemplates();
}

export function createAutomation() {
    const modal = document.getElementById('createAutomationModal');
    if (modal) modal.style.display = 'flex';
}

export function hideCreateAutomationModal() {
    const modal = document.getElementById('createAutomationModal');
    if (modal) modal.style.display = 'none';
}

export async function submitCreateAutomation() {
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
            icon: category === 'investment' ? '💰' : category === 'dev' ? '💻' : category === 'marketing' ? '📈' : '🤖',
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

export async function openTemplateDetail(templateId) {
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

export function hideTemplateDetailModal() {
    const modal = document.getElementById('templateDetailModal');
    if (modal) modal.style.display = 'none';
}

export function runTemplate(id) {
    const tid = id || currentTemplateId;
    if (!tid) {
        showToast('No template selected', 'error');
        return;
    }
    const template = templateData.find(t => t.id === tid);
    const name = template?.name || tid;
    
    showToast(`Running: ${name}...`, 'success');
    hideTemplateDetailModal();
    
    if (window.appendSessionLog) window.appendSessionLog(`Launching workflow: ${name} [${tid}]`, 'info');
    
    // Simulate progress
    setTimeout(() => { if (window.appendSessionLog) window.appendSessionLog(`[${tid}] Initializing environment...`, 'system'); }, 500);
    setTimeout(() => { if (window.appendSessionLog) window.appendSessionLog(`[${tid}] Running step 1 of ${template?.steps?.length || '?'}: ${template?.steps?.[0]?.description || 'Initiating'}`, 'system'); }, 1500);
}
