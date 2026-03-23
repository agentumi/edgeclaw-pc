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
    // Default to the EdgeClaw standard WebSocket port (9460) instead of guessing base+1
    const wsPort = overridePort ? Number(overridePort) : 9460;

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

    // Restore language preference
    const langSelect = document.getElementById('aiChatLangSelect');
    if (langSelect) {
        const savedLang = localStorage.getItem('edgeclaw_chat_lang');
        if (savedLang) langSelect.value = savedLang;
        
        langSelect.addEventListener('change', () => {
            localStorage.setItem('edgeclaw_chat_lang', langSelect.value);
        });
    }

    let sending = false;
    let allQuickActions = [];
    let currentProfileFilter = 'all';

    // Hydrate chat history from backend on startup
    apiFetch(`${API}/api/chat/history`)
        .then(res => res.json())
        .then(history => {
            if (history && Array.isArray(history)) {
                history.forEach(msg => {
                    const role = msg.role.toLowerCase();
                    if (role === 'system') return; // Hide internal system prompts from UI by default
                    addMsg(role === 'user' ? 'user' : 'agent', msg.content, null);
                });
                chatArea.scrollTop = chatArea.scrollHeight;
            }
        })
        .catch(err => console.error("[V2.3] Failed to hydrate chat history:", err));

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

        const langSelect = document.getElementById('aiChatLangSelect');
        const lang = langSelect ? langSelect.value : (localStorage.getItem('edgeclaw_chat_lang') || 'english');
        if (langSelect) localStorage.setItem('edgeclaw_chat_lang', lang);

        try {
            const res = await apiFetch(`${API}/api/chat`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    message: text,
                    lang: lang
                }),
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

            // Intelligent JSON-to-Mission Parser (Collective Intelligence Bridge)
            let missionData = data.intent && data.intent.mission ? data.intent.mission : null;
            if (!missionData && data.message && data.message.includes('{')) {
                try {
                    const extracted = JSON.parse(data.message.substring(data.message.indexOf('{'), data.message.lastIndexOf('}') + 1));
                    if (extracted.mission) missionData = extracted.mission;
                    else if (extracted.id && extracted.tasks) missionData = extracted;
                } catch(e) {}
            }

            if (missionData) {
                const mission = missionData;
                const tasksHtml = (mission.tasks || []).map(t => `
                    <div style="display:flex; gap:10px; align-items:center; background:rgba(0,0,0,0.2); padding:8px 12px; border-radius:8px; border-left:2px solid var(--primary-500); margin-bottom:6px;">
                        <i class="fa-solid fa-microchip" style="font-size:10px; color:var(--text-muted)"></i>
                        <span style="font-size:11px; color:var(--text-primary); flex:1;">${t.desc}</span>
                        <span style="font-size:9px; background:var(--surface-900); padding:2px 6px; border-radius:4px; color:var(--primary-300); font-family:monospace;">${t.capability}</span>
                    </div>
                `).join('');

                content += `
                    <div class="mission-proposal-card" style="margin-top:20px; background:linear-gradient(135deg, rgba(88, 28, 135, 0.1), rgba(124, 58, 237, 0.1)); border:1px solid var(--primary-500); border-radius:16px; padding:20px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); border-top: 4px solid var(--primary-500);">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                            <div style="color:var(--primary-400); font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:2px; display:flex; align-items:center; gap:8px;">
                                <i class="fa-solid fa-sparkles"></i> MISSION PROPOSED
                            </div>
                            <div style="background:var(--primary-600); color:white; font-size:9px; font-weight:700; padding:3px 10px; border-radius:100px; box-shadow: 0 0 15px var(--primary-900);">ATOMIC CI</div>
                        </div>
                        <div style="font-size:18px; font-weight:800; color:white; margin-bottom:4px; font-family:'Inter', sans-serif;">${mission.title || 'Untitled Mission'}</div>
                        <div style="font-size:13px; color:var(--text-muted); line-height:1.5; margin-bottom:16px;">${mission.description || 'No description provided.'}</div>
                        
                        <div style="margin-bottom:20px;">
                            <div style="font-size:10px; color:var(--text-muted); text-transform:uppercase; margin-bottom:8px; font-weight:600;">Task Orchestration</div>
                            ${tasksHtml}
                        </div>

                        <button id="btn-activate-${mission.id}" class="btn-primary" style="width:100%; padding:14px; font-size:14px; font-weight:700; background:linear-gradient(to right, var(--primary-600), var(--accent-purple)); border:none; box-shadow:0 4px 15px rgba(124, 58, 237, 0.3);" onclick="confirmMission('${mission.id}', this)">
                            <i class="fa-solid fa-bolt-lightning" style="margin-right:10px;"></i> ACTIVATE COLLECTIVE MISSION
                        </button>
                        <div style="text-align:center; font-size:9px; color:var(--text-muted); margin-top:10px;">Security: All tasks require owner-defined capability tokens.</div>
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
                <div style="display:flex; align-items:center; gap:10px; opacity:0.8;">
                    <div class="typing-indicator active" style="position:relative; background:transparent; padding:0;"><div class="dots" style="position:static;"><span></span><span></span><span></span></div></div>
                    <span id="orch-timer" style="font-size:11px; font-family:monospace; color:var(--primary-400); font-weight:700; margin-left:4px;">0.0s</span>
                    <span style="font-size:11px; color:var(--text-muted); font-weight:600; text-transform:uppercase; letter-spacing:1px;">Orchestrating...</span>
                </div>
            </div>`;
        messagesArea.appendChild(agentDiv);
        messagesArea.scrollTop = messagesArea.scrollHeight;

        // High-Precision Orchestration Timer
        const startTime = Date.now();
        const timerInterval = setInterval(() => {
            const timerEl = document.getElementById('orch-timer');
            if (timerEl) {
                const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
                timerEl.textContent = `${elapsed}s`;
            } else {
                clearInterval(timerInterval);
            }
        }, 100);

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
            clearInterval(timerInterval); // Stop orchestration pulse

            if (res.ok) {
                const data = await res.json();
                console.log("[EdgeClaw AI] Received payload:", data); // Debugging pulse
                
                const decodeUnicode = (str) => {
                    if (!str || typeof str !== 'string') return str;
                    return str.replace(/\\u([0-9a-fA-F]{4})/g, (match, grp) => {
                        return String.fromCharCode(parseInt(grp, 16));
                    });
                };

                const rawMsg = data.message || '';
                
                // 1. Resilient Unicode & Byte-Level Sanitizer
                const sanitizeAndDecode = (str) => {
                    if (!str || typeof str !== 'string') return str;
                    // Remove trailing partial escapes and artifacts
                    let sanitized = str.replace(/\\u[0-9a-fA-F]{0,3}$/, '');
                    try {
                        return sanitized.replace(/\\u([0-9a-fA-F]{4})/g, (match, grp) => {
                            return String.fromCharCode(parseInt(grp, 16));
                        });
                    } catch(e) { return sanitized; }
                };

                const cleanedMsg = sanitizeAndDecode(rawMsg);
                let mainText = cleanedMsg;
                let missionData = null;

                // 2. High-Fidelity Extraction Engine
                if (data.intent && data.intent.mission) {
                    missionData = data.intent.mission;
                }

                if (!missionData && cleanedMsg.includes('{')) {
                    try {
                        const start = cleanedMsg.indexOf('{');
                        const end = cleanedMsg.lastIndexOf('}');
                        if (start >= 0 && end > start) {
                            const candidate = cleanedMsg.substring(start, end + 1);
                            const parsed = JSON.parse(candidate);
                            if (parsed.intent && parsed.intent.mission) missionData = parsed.intent.mission;
                            else if (parsed.mission) missionData = parsed.mission;
                            else if (parsed.id && parsed.tasks) missionData = parsed;
                            
                            // If mission found, trim the junk from main text
                            if (missionData && start > 5) mainText = cleanedMsg.substring(0, start).trim();
                            else if (missionData) mainText = ""; // Hide raw JSON if card is ready
                        }
                    } catch(e) {}
                }

                // 3. UI Cleanup: Only show text if it's not a raw JSON dump
                let isJsonDump = mainText.trim().startsWith('{') && mainText.trim().endsWith('}');
                let html = (isJsonDump && missionData) ? "" : mainText
                    .replace(/\n/g, '<br>')
                    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                    .replace(/`(.*?)`/g, '<code style="background:var(--surface-700); padding:2px 4px; border-radius:4px;">$1</code>');
                
                if (missionData) {
                    const mission = missionData;
                    const mTitle = sanitizeAndDecode(mission.title) || "Dynamic Mission Orchestration";
                    const mDesc = sanitizeAndDecode(mission.description) || "AI-generated collective intelligence workflow for your current objective.";
                    
                    const tasksHtml = (mission.tasks || []).map(t => {
                        const tDesc = sanitizeAndDecode(t.desc) || "Executing atomic capability...";
                        return `
                            <div style="display:flex; gap:10px; align-items:center; background:rgba(0,0,0,0.3); padding:10px 14px; border-radius:10px; border-left:3px solid var(--primary-500); margin-bottom:8px; box-shadow:0 2px 5px rgba(0,0,0,0.2);">
                                <div style="width:20px; height:20px; border-radius:50%; background:var(--surface-600); display:flex; align-items:center; justify-content:center; font-size:9px; color:var(--primary-400); flex-shrink:0;">
                                    <i class="fa-solid fa-microchip"></i>
                                </div>
                                <span style="font-size:12px; color:var(--text-primary); flex:1; font-weight:500;">${tDesc}</span>
                                <span style="font-size:9px; background:var(--primary-900); padding:3px 8px; border-radius:6px; color:var(--primary-200); font-family:monospace; font-weight:800; text-transform:uppercase; letter-spacing:0.5px;">${t.capability}</span>
                            </div>
                        `;
                    }).join('');

                    html += `
                        <div class="mission-proposal-card" style="margin-top:10px; background:linear-gradient(165deg, rgba(88, 28, 135, 0.2), rgba(124, 58, 237, 0.1)); border:2px solid var(--primary-600); border-radius:20px; padding:24px; box-shadow: 0 15px 40px rgba(0,0,0,0.4); border-top: 6px solid var(--primary-500); position:relative; overflow:hidden; animation: slideInUp 0.4s ease-out;">
                            <div style="position:absolute; top:-20px; right:-20px; width:100px; height:100px; background:var(--primary-500); opacity:0.1; border-radius:50%; filter:blur(40px);"></div>
                            
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
                                <div style="color:var(--primary-300); font-size:11px; font-weight:900; text-transform:uppercase; letter-spacing:2px; display:flex; align-items:center; gap:8px;">
                                    <i class="fa-solid fa-sparkles fa-beat" style="--fa-animation-duration: 2s;"></i> ATOMIC MISSION READY
                                </div>
                                <div style="background:rgba(255,255,255,0.05); padding:4px 10px; border-radius:6px; font-size:10px; color:var(--text-muted); font-family:monospace;">${mission.id || 'mission-auto'}</div>
                            </div>
                            
                            <div style="font-size:20px; font-weight:900; color:white; margin-bottom:8px; letter-spacing:-0.5px;">${mTitle}</div>
                            <div style="font-size:14px; color:var(--text-muted); line-height:1.6; margin-bottom:20px; border-left:2px solid var(--surface-600); padding-left:12px;">${mDesc}</div>
                            
                            <div style="margin-bottom:24px;">
                                <div style="font-size:10px; color:var(--primary-400); text-transform:uppercase; margin-bottom:12px; font-weight:800; letter-spacing:1px;">Orchestration Plan</div>
                                ${tasksHtml}
                            </div>

                            <button class="btn-primary" style="width:100%; padding:16px; font-size:14px; font-weight:800; background:linear-gradient(to right, var(--primary-600), var(--accent-purple)); border:none; box-shadow:0 8px 20px rgba(124, 58, 237, 0.4); cursor:pointer;" onclick="window.confirmMission && window.confirmMission('${mission.id}', this)">
                                <i class="fa-solid fa-bolt-lightning" style="margin-right:12px;"></i> ACTIVATE MISSION
                            </button>
                        </div>
                    `;
                }

                contentDiv.innerHTML = html;
            } else {
                let errorMsg = "Failed to generate response. Check if Local AI is reachable.";
                try {
                    const errorData = await res.json();
                    if (errorData.error) errorMsg = errorData.error;
                } catch(e) {}
                
                contentDiv.innerHTML = `<div style="padding:12px; background:rgba(239, 68, 68, 0.1); border:1px solid var(--accent-red); border-radius:8px; display:flex; gap:10px; align-items:center;">
                    <i class="fa-solid fa-triangle-exclamation" style="color:var(--accent-red)"></i>
                    <span style="color:var(--accent-red)">${errorMsg}</span>
                </div>`;
            }
        } catch (e) {
            const contentDiv = agentDiv.querySelector('.agent-msg-content');
            if (contentDiv) {
                contentDiv.innerHTML = `<div style="padding:12px; background:rgba(239, 68, 68, 0.1); border:1px solid var(--accent-red); border-radius:8px; display:flex; gap:10px; align-items:center;">
                    <i class="fa-solid fa-plug-circle-xmark" style="color:var(--accent-red)"></i>
                    <span style="color:var(--accent-red)">Connection error. Ensure the EdgeClaw backend is running.</span>
                </div>`;
            }
        }
        messagesArea.scrollTop = messagesArea.scrollHeight;
    }
}

export function showChatHelp() {
    const helpText = `
        <div style="text-align:left; font-size:12px; line-height:1.6;">
            <strong>Commands:</strong><br>
            ??<code>/mode [sanctum|high-perf]</code>: UI theme switch<br>
            ??<code>/model [name]</code>: Select specific AI model<br>
            ??<code>/models</code>: List all local models<br>
            ??<code>/parallel [m1,m2]</code>: Task consensus<br>
            ??<code>@[agent]</code>: Route to specific agent<br>
            ??<code>/mission [title]</code>: Setup new workflow<br><br>
            <em>All data is processed strictly locally by default.</em>
        </div>
    `;
    // Use a custom modal or toast
    if (window.showToast) {
        window.showToast('Chat Commands: /mode, /model, /models, /parallel, @mention, /mission', 'info');
    }
    
    // For richer help, let's append a system message to the chat
    const log = document.getElementById('aiChatMessages');
    if (log) {
        const div = document.createElement('div');
        div.style.background = 'var(--surface-800)';
        div.style.padding = '16px';
        div.style.borderRadius = '12px';
        div.style.border = '1px solid var(--surface-700)';
        div.style.marginBottom = '16px';
        div.innerHTML = `
            <div style="font-weight:600; color:var(--primary-400); margin-bottom:8px;"><i class="fa-solid fa-circle-question"></i> Chat Help</div>
            ${helpText}
        `;
        log.appendChild(div);
        log.scrollTop = log.scrollHeight;
    }
}

export function confirmMission(missionId, el) {
    if (!missionId) return;
    
    // Immediate UI feedback
    if (el) {
        el.disabled = true;
        el.innerHTML = '<i class="fa-solid fa-sync fa-spin"></i> Activating Mission...';
        el.style.background = 'var(--surface-600)';
    }

    apiFetch(`${API}/api/mission/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mission_id: missionId })
    })
    .then(async res => {
        if (res.ok) {
            if (window.showToast) window.showToast('Mission activated! Starting autonomous execution...', 'success');
            
            // Poll for progress and update the button live
            if (el) {
                const pollInterval = setInterval(async () => {
                    try {
                        const statusRes = await apiFetch(`${API}/api/v1/mission/active`);
                        if (statusRes.ok) {
                            const data = await statusRes.json();
                            if (data.id === missionId) {
                                const pct = data.progress ?? 0;
                                const status = (data.status || 'Active').toUpperCase();
                                el.innerHTML = `<i class="fa-solid fa-microchip"></i> ${status}: ${pct}%`;
                                
                                // Successful completion
                                if (pct >= 100 || status === 'SUCCESS' || status === 'COMPLETED') {
                                    el.innerHTML = '<i class="fa-solid fa-check-double"></i> MISSION SUCCESSFUL';
                                    el.style.background = 'var(--accent-green)';
                                    clearInterval(pollInterval);
                                }
                            }
                        }
                    } catch (e) {
                         console.error("Button poll error:", e);
                         clearInterval(pollInterval);
                    }
                }, 10000); // 10s poll to match heartbeat
            }

            // V2.4 Refresh dashboard data immediately
            if (window.fetchDashboardData) window.fetchDashboardData();
        } else {
            console.error('Failed to confirm mission');
            if (window.showToast) window.showToast('Failed to activate mission.', 'error');
            if (el) {
                el.disabled = false;
                el.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> Activation Failed';
            }
        }
    })
    .catch(err => {
        console.error('Error confirming mission:', err);
        if (window.showToast) window.showToast('Network error while activating.', 'error');
        if (el) {
            el.disabled = false;
            el.innerHTML = '<i class="fa-solid fa-bolt-lightning"></i> Retry Activation';
        }
    });
}

window.confirmMission = confirmMission;
