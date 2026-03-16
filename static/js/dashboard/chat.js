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
