import { API, apiFetch, showToast, setTranslatedText } from './core.js';

export let lastTasks = [];

export function taskColumnId(status) {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'backlog' || normalized === 'todo') return 'todo';
    if (normalized === 'inprogress' || normalized === 'in_progress' || normalized === 'progress' || normalized === 'review') return 'progress';
    if (normalized === 'done') return 'done';
    return 'todo';
}

export async function fetchTasks(selectedAgentId, dragCallback) {
    try {
        const query = selectedAgentId ? `?assignee=${encodeURIComponent(selectedAgentId)}` : '';
        const res = await apiFetch(`${API}/api/tasks${query}`);
        if (!res.ok) throw new Error(`tasks ${res.status}`);
        const tasks = await res.json();
        lastTasks = tasks;
        
        document.querySelectorAll('#col-todo .kanban-cards, #col-progress .kanban-cards, #col-done .kanban-cards')
            .forEach(c => c.innerHTML = '');
        
        tasks.forEach(task => {
            const col = document.getElementById(`col-${taskColumnId(task.status)}`) || document.getElementById('col-todo');
            const container = col.querySelector('.kanban-cards');
            const card = document.createElement('div');
            card.className = 'task-card';
            card.draggable = true;
            card.id = `task-${task.id}`;
            card.dataset.id = task.id;
            const titleText = task.title || '';
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
            if (dragCallback) card.ondragstart = dragCallback;
            card.ondblclick = () => quickAssignTask(task.id, selectedAgentId);
            container.appendChild(card);
        });

        const todoCount = document.querySelectorAll('#col-todo .kanban-cards .task-card').length;
        const progCount = document.querySelectorAll('#col-progress .kanban-cards .task-card').length;
        const doneCount = document.querySelectorAll('#col-done .kanban-cards .task-card').length;
        document.querySelector('#col-todo .kanban-header .badge').textContent = todoCount;
        document.querySelector('#col-progress .kanban-header .badge').textContent = progCount;
        document.querySelector('#col-done .kanban-header .badge').textContent = doneCount;

        if (window.renderTaskOverview) window.renderTaskOverview(tasks);
    } catch(e) {
        showToast("Failed to load tasks", "error");
    }
}

export async function quickAssignTask(taskId, selectedAgentId, cachedAgents = []) {
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
            if (window.fetchTasks) window.fetchTasks();
        } else {
            showToast('Failed to assign task', 'error');
        }
    } catch (e) {
        showToast('Failed to assign task', 'error');
    }
}

export function populateTaskAssigneeOptions(cachedAgents, selectedAgentId) {
    const select = document.getElementById('taskAssigneeInput');
    if (!select) return;

    const assignees = cachedAgents.length > 0
        ? cachedAgents
        : [{ id: selectedAgentId || 'local', name: 'local' }];

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

export function showNewTaskModal(cachedAgents, selectedAgentId) {
    const modal = document.getElementById('newTaskModal');
    if (!modal) return;
    populateTaskAssigneeOptions(cachedAgents, selectedAgentId);
    modal.style.display = 'flex';
    const title = document.getElementById('taskTitleInput');
    if (title) title.focus();
}

export function hideNewTaskModal() {
    const modal = document.getElementById('newTaskModal');
    if (modal) modal.style.display = 'none';

    const form = document.getElementById('newTaskForm');
    if (form) form.reset();

    const tags = document.getElementById('taskTagsInput');
    if (tags) tags.value = 'dashboard';

    const priority = document.getElementById('taskPriorityInput');
    if (priority) priority.value = 'Medium';
}

export async function submitNewTask() {
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
        if (window.fetchTasks) window.fetchTasks();
    } catch (e) {
        showToast(`Failed to create task: ${e?.message || 'unknown error'}`, 'error');
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalBtn;
        }
    }
}
