import { API, apiFetch, AppState } from './core.js';

function resolveWsUrl() {
    if (window.EDGECLAW_WS_URL) return window.EDGECLAW_WS_URL;

    const params = new URLSearchParams(window.location.search);
    const overridePort = window.EDGECLAW_WS_PORT || params.get('ws_port') || localStorage.getItem('edgeclaw_ws_port');
    if (params.get('ws_port')) {
        localStorage.setItem('edgeclaw_ws_port', params.get('ws_port'));
    }

    const apiUrl = new URL(API);
    const protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    const basePort = apiUrl.port ? Number(apiUrl.port) : (apiUrl.protocol === 'https:' ? 443 : 80);
    const wsPort = overridePort ? Number(overridePort) : basePort + 1;

    return `${protocol}//${apiUrl.hostname}:${wsPort}`;
}

export function initChat({ getCurrentMode, appendSessionLog, renderEconomy, fetchMemory } = {}) {
    const chatArea = document.getElementById('chatArea');
    const chatInput = document.getElementById('chatInput');
    const sendBtn = document.getElementById('sendBtn');
    const typingIndicator = document.getElementById('typingIndicator');
    const chatQuickActions = document.getElementById('chatQuickActions');
    const chatStatusText = document.getElementById('chatStatusText');
    const profileTabs = document.getElementById('chatProfiles');

    if (!chatArea || !chatInput || !sendBtn) return;

    let sending = false;
    let allQuickActions = [];
    let currentProfileFilter = 'all';

    const resolveMode = () => (typeof getCurrentMode === 'function' ? getCurrentMode() : 'sanctum');

    chatInput.addEventListener('input', () => {
        chatInput.style.height = 'auto';
        chatInput.style.height = Math.min(chatInput.scrollHeight, 120) + 'px';
    });

    chatInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendChatMessage();
        }
    });

    sendBtn.addEventListener('click', sendChatMessage);

    async function sendChatMessage() {
        const text = chatInput.value.trim();
        if (!text || sending) return;

        sending = true;
        sendBtn.disabled = true;
        addMsg('user', text);
        chatInput.value = '';
        chatInput.style.height = 'auto';

        typingIndicator.classList.add('active');
        chatArea.scrollTop = chatArea.scrollHeight;

        try {
            const res = await apiFetch(`${API}/api/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text }),
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}`);

            const data = await res.json();
            addMsg('agent', data.message, data);
        } catch (err) {
            if (err.message !== 'Rate limited') {
                addMsg('system', `Communication Error: ${err.message}`);
            }
        } finally {
            typingIndicator.classList.remove('active');
            sending = false;
            sendBtn.disabled = false;
            chatInput.focus();
        }
    }

    function addMsg(role, text, data) {
        const div = document.createElement('div');
        div.className = `msg ${role}`;

        let content = text.replace(/`([^`]+)`/g, '<code>$1</code>');
        content = content.replace(/\n/g, '<br>');

        const privacyIcon = resolveMode() === 'sanctum'
            ? '<i class="fa-solid fa-lock" style="font-size:10px; margin-right:4px; opacity:0.6"></i>'
            : '<i class="fa-solid fa-earth-americas" style="font-size:10px; margin-right:4px; color:var(--accent-purple)"></i>';

        let metaHtml = '';
        if (role === 'agent' && data) {
            const provider = data.provider || 'AI';
            const confidence = data.confidence ? (data.confidence * 100).toFixed(0) : '?';
            metaHtml = `<div class="msg-info">${privacyIcon} ${provider} - ${confidence}% accuracy - ${new Date().toLocaleTimeString()}</div>`;

            if (data.exec_result) {
                const exec = data.exec_result;
                const statusClass = exec.success ? 'success' : 'error';
                const statusText = exec.success ? 'SUCCESS' : 'FAILED';
                content += `
                    <div class="exec-result-box">
                        <div class="exec-header ${statusClass}">
                            <span>EXECUTED: ${statusText}</span>
                            <span>${exec.duration_ms || 0}ms</span>
                        </div>
                        <div class="exec-body">${exec.stdout || exec.stderr || '(no output)'}</div>
                    </div>
                `;
            }
        } else if (role === 'user') {
            metaHtml = `<div class="msg-info" style="text-align:right">${privacyIcon} ${new Date().toLocaleTimeString()}</div>`;
        }

        div.innerHTML = `<div class="msg-bubble">${content}</div>${metaHtml}`;
        chatArea.appendChild(div);
        chatArea.scrollTop = chatArea.scrollHeight;
    }

    async function loadQuickActions() {
        try {
            const res = await apiFetch(`${API}/api/quick-actions`);
            if (!res.ok) return;
            allQuickActions = await res.json();
            renderQuickActions();
        } catch (_) {}
    }

    function renderQuickActions() {
        if (!chatQuickActions) return;
        chatQuickActions.innerHTML = '';
        const filtered = currentProfileFilter === 'all'
            ? allQuickActions
            : allQuickActions.filter(a => a.profile === currentProfileFilter || a.profile === 'System');

        filtered.forEach(action => {
            const icon = iconForQuickAction(action);
            const btn = document.createElement('button');
            btn.className = `qa-btn qa-icon ${action.needs_confirmation ? 'confirm' : ''}`;
            btn.dataset.tooltip = action.label || action.command || 'Quick Action';
            btn.title = action.label || action.command || 'Quick Action';
            btn.innerHTML = `<i class="fa-solid ${icon}"></i>`;
            btn.onclick = () => {
                chatInput.value = action.command;
                sendChatMessage();
            };
            chatQuickActions.appendChild(btn);
        });
    }

    function iconForQuickAction(action) {
        const label = String(action.label || '').toLowerCase();
        const command = String(action.command || '').toLowerCase();
        const hay = `${label} ${command}`;

        if (hay.includes('cpu')) return 'fa-microchip';
        if (hay.includes('memory')) return 'fa-memory';
        if (hay.includes('disk') || hay.includes('storage')) return 'fa-hard-drive';
        if (hay.includes('network')) return 'fa-network-wired';
        if (hay.includes('port')) return 'fa-plug';
        if (hay.includes('service')) return 'fa-sliders';
        if (hay.includes('uptime')) return 'fa-clock';
        if (hay.includes('docker')) return 'fa-docker';
        if (hay.includes('git') && hay.includes('pull')) return 'fa-arrow-down';
        if (hay.includes('git') && hay.includes('push')) return 'fa-arrow-up';
        if (hay.includes('git')) return 'fa-code-branch';
        if (hay.includes('build')) return 'fa-hammer';
        if (hay.includes('test')) return 'fa-vial';
        if (hay.includes('lint') || hay.includes('clippy')) return 'fa-broom';
        if (hay.includes('format')) return 'fa-paintbrush';
        if (hay.includes('deploy') || hay.includes('release')) return 'fa-rocket';
        if (hay.includes('restart')) return 'fa-rotate';
        if (hay.includes('backup') || hay.includes('db')) return 'fa-database';
        if (hay.includes('security') || hay.includes('audit')) return 'fa-shield-halved';
        if (hay.includes('report') || hay.includes('analytics')) return 'fa-chart-line';
        if (hay.includes('campaign') || hay.includes('marketing')) return 'fa-bullhorn';
        if (hay.includes('help') || hay.includes('command')) return 'fa-terminal';
        if (hay.includes('status')) return 'fa-heart-pulse';
        return 'fa-bolt';
    }

    if (profileTabs) {
        profileTabs.addEventListener('click', (e) => {
            const target = e.target;
            if (target && target.dataset.profile) {
                document.querySelectorAll('.chat-tab').forEach(t => t.classList.remove('active'));
                target.classList.add('active');
                currentProfileFilter = target.dataset.profile;
                renderQuickActions();
            }
        });
    }

    function initWebSocket() {
        if (!chatStatusText) return;
        const wsUrl = resolveWsUrl();
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log('WS Connected');
            chatStatusText.textContent = 'Live';
            chatStatusText.style.color = 'var(--accent-green)';
        };

        ws.onmessage = (e) => {
            try {
                const event = JSON.parse(e.data);
                const type = event.type;
                const payload = event.data;

                switch (type) {
                    case 'Alert':
                        addMsg('system', `ALERT: ${payload.message}`);
                        if (appendSessionLog) appendSessionLog(`Alert: ${payload.message}`, 'warn');
                        break;
                    case 'CommandStarted':
                        addMsg('system', `[EXECUTING] ${payload.command}`);
                        if (appendSessionLog) appendSessionLog(`Executing: ${payload.command}`, 'info');
                        break;
                    case 'CommandCompleted':
                        const status = payload.success ? 'Success' : 'Failed';
                        addMsg('system', `[${status}] Command finished in ${payload.duration_ms}ms (code: ${payload.exit_code ?? '?'})`);
                        if (appendSessionLog) appendSessionLog(`Command ${status.toLowerCase()}: ${payload.command}`, payload.success ? 'info' : 'error');
                        break;
                    case 'PeerConnected':
                        addMsg('system', `Peer connected: ${payload.device_name || payload.peer_id}`);
                        if (appendSessionLog) appendSessionLog(`Peer connected: ${payload.device_name || payload.peer_id}`, 'info');
                        break;
                    case 'PeerDisconnected':
                        addMsg('system', `Peer disconnected: ${payload.peer_id}`);
                        if (appendSessionLog) appendSessionLog(`Peer disconnected: ${payload.peer_id}`, 'warn');
                        break;
                    case 'StatusChange':
                        addMsg('system', `Status changed: ${payload.previous} -> ${payload.current}`);
                        if (appendSessionLog) appendSessionLog(`Status: ${payload.previous} -> ${payload.current}`, 'info');
                        break;
                    case 'MetricUpdate':
                        if (payload.status && renderEconomy) renderEconomy(payload.status);
                        break;
                    case 'MemoryUpdated':
                        if (AppState.get('currentView') === 'view-memory' && fetchMemory) {
                            fetchMemory();
                        }
                        break;
                }
            } catch (_) {}
        };

        ws.onclose = () => {
            chatStatusText.textContent = 'Reconnecting...';
            chatStatusText.style.color = 'var(--accent-gold)';
            setTimeout(initWebSocket, 5000);
        };
    }

    loadQuickActions();
    initWebSocket();
}

export function initAIChat() {
    const input = document.getElementById('aiChatInput');
    const sendBtn = document.getElementById('aiChatSendBtn');
    const messagesArea = document.getElementById('aiChatMessages');
    const initialPrompt = document.getElementById('aiChatInitial');
    const modelSelect = document.getElementById('aiChatModelSelect');
    const attachBtn = document.getElementById('aiChatAttachBtn');
    const fileInput = document.getElementById('aiChatFile');
    const attachmentPreview = document.getElementById('aiChatAttachments');
    
    if (!input || !sendBtn || !messagesArea) return;

    let currentAttachments = [];

    // Helper to remove attachment (exposed to window for onclick)
    window.removeAIAttachment = (index) => {
        currentAttachments.splice(index, 1);
        renderAttachments();
    };

    function renderAttachments() {
        if (currentAttachments.length > 0) {
            attachmentPreview.style.display = 'flex';
            attachmentPreview.innerHTML = currentAttachments.map((a, i) => `
                <div style="background:var(--surface-700); padding:6px 12px; border-radius:12px; font-size:11px; display:flex; align-items:center; gap:8px; border:1px solid var(--surface-600); box-shadow:0 2px 4px rgba(0,0,0,0.1);">
                    <i class="fa-solid ${a.mime_type.startsWith('image/') ? 'fa-image' : 'fa-file-lines'}" style="color:var(--primary-400)"></i>
                    <span style="max-width:150px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-primary);">${a.name}</span>
                    <i class="fa-solid fa-xmark" style="cursor:pointer; color:var(--text-muted); font-size:12px; hover:color:var(--accent-red);" onclick="removeAIAttachment(${i})"></i>
                </div>
            `).join('');
        } else {
            attachmentPreview.style.display = 'none';
        }
    }

    if (attachBtn && fileInput) {
        attachBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', async (e) => {
            const files = Array.from(e.target.files);
            for (const file of files) {
                const reader = new FileReader();
                reader.onload = (ev) => {
                    const base64 = ev.target.result.split(',')[1];
                    currentAttachments.push({
                        name: file.name,
                        mime_type: file.type,
                        content_base64: base64
                    });
                    renderAttachments();
                };
                reader.readAsDataURL(file);
            }
            fileInput.value = '';
        });
    }

    // Load available models from the backend
    async function loadModels() {
        if (!modelSelect) return;
        try {
            const res = await apiFetch(`${API}/api/chat/models`);
            if (res.ok) {
                const models = await res.json();
                if (models && models.length > 0) {
                    const currentVal = modelSelect.value;
                    modelSelect.innerHTML = '<option value="">Auto-select (Local)</option>' + 
                        models.map(m => `<option value="${m}" ${m === currentVal ? 'selected' : ''}>${m}</option>`).join('');
                }
            }
        } catch (e) {
            console.error("AI: Failed to load models:", e);
        }
    }
    loadModels();

    input.addEventListener('input', () => {
        input.style.height = 'auto';
        input.style.height = Math.min(input.scrollHeight, 160) + 'px';
        const hasContent = input.value.trim().length > 0 || currentAttachments.length > 0;
        sendBtn.style.background = hasContent ? 'var(--primary-600)' : 'var(--text-muted)';
        sendBtn.style.color = hasContent ? 'white' : 'var(--surface-900)';
    });

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendAIChat();
        }
    });

    sendBtn.addEventListener('click', sendAIChat);

    async function sendAIChat() {
        const text = input.value.trim();
        const attachments = [...currentAttachments];
        if (!text && attachments.length === 0) return;

        if (initialPrompt) {
            initialPrompt.style.display = 'none';
        }

        const userDiv = document.createElement('div');
        userDiv.style.display = 'flex';
        userDiv.style.flexDirection = 'column';
        userDiv.style.alignItems = 'flex-end';
        userDiv.style.gap = '8px';
        
        let attachmentHtml = '';
        if (attachments.length > 0) {
            attachmentHtml = `<div style="display:flex; gap:8px; flex-wrap:wrap; justify-content:flex-end; margin-bottom:4px;">` + 
                attachments.map(a => `
                    <div style="background:var(--surface-700); padding:4px 10px; border-radius:8px; font-size:11px; border:1px solid var(--surface-600);">
                        <i class="fa-solid ${a.mime_type.startsWith('image/') ? 'fa-image' : 'fa-file-lines'}"></i> ${a.name}
                    </div>
                `).join('') + `</div>`;
        }

        userDiv.innerHTML = `
            ${attachmentHtml}
            <div style="background:var(--surface-800); border:1px solid var(--surface-700); padding:12px 16px; border-radius:16px; border-bottom-right-radius:4px; max-width:80%; font-size:14px; line-height:1.5; color:var(--text-primary); box-shadow:0 4px 8px rgba(0,0,0,0.1);">
                ${text.replace(/\n/g, '<br>')}
            </div>`;
        messagesArea.appendChild(userDiv);

        // Reset inputs
        input.value = '';
        currentAttachments = [];
        renderAttachments();
        input.style.height = 'auto';
        input.dispatchEvent(new Event('input'));
        messagesArea.scrollTop = messagesArea.scrollHeight;

        const agentDiv = document.createElement('div');
        agentDiv.style.display = 'flex';
        agentDiv.style.gap = '16px';
        agentDiv.innerHTML = `
            <div style="width:32px; height:32px; border-radius:8px; background:linear-gradient(135deg, var(--primary-500), var(--accent-purple)); display:flex; align-items:center; justify-content:center; color:white; font-size:14px; flex-shrink:0; box-shadow:0 4px 8px rgba(0,0,0,0.2);">
                <i class="fa-solid fa-sparkles"></i>
            </div>
            <div class="agent-msg-content" style="flex:1; padding-top:6px; font-size:14px; line-height:1.6; color:var(--text-primary);">
                <div class="typing-indicator active" style="position:relative; background:transparent; padding:0;"><div class="dots" style="position:static;"><span></span><span></span><span></span></div></div>
            </div>`;
        messagesArea.appendChild(agentDiv);
        messagesArea.scrollTop = messagesArea.scrollHeight;

        try {
            const selectedModel = modelSelect ? modelSelect.value : "";
            const res = await apiFetch(`${API}/api/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    message: text, 
                    model: selectedModel || null,
                    attachments: attachments.length > 0 ? attachments : null
                })
            });

            const contentDiv = agentDiv.querySelector('.agent-msg-content');
            if (res.ok) {
                const data = await res.json();
                // Simple markdown-to-html for bold and code
                let html = (data.message || '')
                    .replace(/\n/g, '<br>')
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/`(.*?)`/g, '<code style="background:var(--surface-700); padding:2px 4px; border-radius:4px;">$1</code>');
                
                contentDiv.innerHTML = html;
            } else {
                contentDiv.innerHTML = `<div style="padding:12px; background:rgba(239, 68, 68, 0.1); border:1px solid var(--accent-red); border-radius:8px; display:flex; gap:10px; align-items:center;">
                    <i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-red)"></i>
                    <span style="color:var(--accent-red)">Failed to generate response. Check if Local AI is reachable.</span>
                </div>`;
            }
        } catch (e) {
            const contentDiv = agentDiv.querySelector('.agent-msg-content');
            contentDiv.innerHTML = `<div style="padding:12px; background:rgba(239, 68, 68, 0.1); border:1px solid var(--accent-red); border-radius:8px; display:flex; gap:10px; align-items:center;">
                <i class="fa-solid fa-plug-circle-xmark" style="color:var(--accent-red)"></i>
                <span style="color:var(--accent-red)">Connection error. Ensure the EdgeClaw backend is running.</span>
            </div>`;
        }
        messagesArea.scrollTop = messagesArea.scrollHeight;
    }
}

