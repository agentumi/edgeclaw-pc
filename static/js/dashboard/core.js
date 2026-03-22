// Core helpers extracted from dashboard.html to keep UI modules lean.

const API_STORAGE_KEY = 'edgeclaw_api_base';
const TOKEN_STORAGE_KEY = 'edgeclaw_session_token';
const TOKEN_EXPIRY_KEY = 'edgeclaw_session_expires_at';
const AUTH_STORAGE_KEY = 'edgeclaw_auth_password';

function normalizeApiBase(value) {
    if (!value) return value;
    return value.replace(/\/+$/, '');
}

function resolveApiBase() {
    const params = new URLSearchParams(window.location.search);
    const queryApi = params.get('api');
    const storedApi = localStorage.getItem(API_STORAGE_KEY);
    const override = window.EDGECLAW_API || queryApi || storedApi;

    if (queryApi) {
        localStorage.setItem(API_STORAGE_KEY, queryApi);
    }

    if (override) return normalizeApiBase(override);

    const origin = window.location.origin;
    if (origin && origin !== 'null' && !origin.startsWith('file:')) {
        return origin;
    }

    return 'http://127.0.0.1:9444';
}

export const API = resolveApiBase();

export const AppState = (() => {
    const _state = {
        missions: [],
        agents: [],
        templates: [],
        tasks: [],
        status: null,
        currentView: 'view-dashboard',
        infraSummary: null,
    };
    const _listeners = {};

    return {
        get(key) { return _state[key]; },
        set(key, value) {
            _state[key] = value;
            if (_listeners[key]) {
                _listeners[key].forEach(fn => { try { fn(value); } catch (e) { console.error('AppState listener error:', e); } });
            }
        },
        subscribe(key, fn) {
            if (!_listeners[key]) _listeners[key] = [];
            _listeners[key].push(fn);
            if (_state[key] !== null && _state[key] !== undefined) fn(_state[key]);
        },
        getAll() { return { ..._state }; },
        register(viewId, config) {
            if (!_state.views) _state.views = {};
            _state.views[viewId] = config;
            console.log(`[AppState] Registered view-logic for: ${viewId}`);
        }
    };
})();

window.AppState = AppState;

export function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        left: 50%;
        transform: translateX(-50%) translateY(100px);
        background: var(--surface-800);
        border: 1px solid var(--surface-700);
        border-left: 4px solid var(--primary-500);
        color: var(--text-primary);
        padding: 12px 24px;
        border-radius: 8px;
        z-index: 9999;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        font-size: 13px;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        display: flex;
        align-items: center;
        gap: 12px;
    `;

    const icon = type === 'success' ? 'check-circle' : (type === 'error' ? 'circle-exclamation' : 'circle-info');
    if (type === 'success') toast.style.borderLeftColor = 'var(--accent-green)';
    if (type === 'error') toast.style.borderLeftColor = 'var(--accent-red)';

    toast.innerHTML = `<i class="fa-solid fa-${icon}"></i> ${message}`;
    document.body.appendChild(toast);

    setTimeout(() => toast.style.transform = 'translateX(-50%) translateY(0)', 10);

    setTimeout(() => {
        toast.style.transform = 'translateX(-50%) translateY(100px)';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
    }, 3000);
}

let sessionToken = localStorage.getItem(TOKEN_STORAGE_KEY) || '';
let sessionExpiresAt = Number(localStorage.getItem(TOKEN_EXPIRY_KEY) || 0);
let loginInFlight = null;

function getValidToken() {
    if (!sessionToken) return null;
    if (sessionExpiresAt && Date.now() > sessionExpiresAt) {
        sessionToken = '';
        localStorage.removeItem(TOKEN_STORAGE_KEY);
        localStorage.removeItem(TOKEN_EXPIRY_KEY);
        return null;
    }
    return sessionToken;
}

function setSession(token, expiresInSeconds) {
    sessionToken = token || '';
    if (!token) return;
    const expiresAt = Date.now() + (Number(expiresInSeconds || 0) * 1000);
    sessionExpiresAt = expiresAt;
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
    if (expiresAt) {
        localStorage.setItem(TOKEN_EXPIRY_KEY, String(expiresAt));
    }
}

async function requestSessionToken(password) {
    try {
        const payload = password ? { password } : {};
        const res = await fetch(`${API}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) return null;
        const data = await res.json();
        if (data?.token) {
            setSession(data.token, data.expires_in || 3600);
            return data.token;
        }
        return null;
    } catch (_) {
        return null;
    }
}

async function ensureSessionToken() {
    const existing = getValidToken();
    if (existing) return existing;
    if (loginInFlight) return loginInFlight;

    loginInFlight = (async () => {
        const storedPassword = window.EDGECLAW_AUTH_PASSWORD || localStorage.getItem(AUTH_STORAGE_KEY);
        let token = await requestSessionToken(storedPassword);
        if (token) return token;

        const password = window.prompt('EdgeClaw Web UI password');
        if (!password) return null;
        localStorage.setItem(AUTH_STORAGE_KEY, password);
        token = await requestSessionToken(password);
        if (!token) {
            showToast('Login failed. Check password.', 'error');
        }
        return token;
    })();

    const result = await loginInFlight;
    loginInFlight = null;
    return result;
}

export async function apiFetch(url, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = getValidToken();
    if (token) {
        headers.set('Authorization', `Bearer ${token}`);
    }

    const baseOptions = { ...options, headers };

    let res = await fetch(url, baseOptions);

    if (res.status === 401) {
        try {
            const data = await res.clone().json();
            if (data?.login_required) {
                const newToken = await ensureSessionToken();
                if (newToken) {
                    headers.set('Authorization', `Bearer ${newToken}`);
                    res = await fetch(url, { ...options, headers });
                }
            }
        } catch (_) {}
    }

    if (res.status === 429) {
        showToast('Rate limit exceeded. Please wait a moment.', 'error');
        throw new Error('Rate limited');
    }

    return res;
}

export function normalizeAgentStatus(status) {
    return String(status || 'offline').toLowerCase();
}

export function taskColumnId(status) {
    const normalized = String(status || '').toLowerCase();
    if (normalized === 'backlog' || normalized === 'todo') return 'todo';
    if (normalized === 'inprogress' || normalized === 'in_progress' || normalized === 'progress' || normalized === 'review') return 'progress';
    if (normalized === 'done') return 'done';
    return 'todo';
}

export function normalizeCapabilities(value) {
    if (Array.isArray(value)) return value.map(v => String(v));
    if (value && typeof value === 'object') return Object.keys(value);
    if (typeof value === 'string' && value.trim()) return [value.trim()];
    return [];
}

export function extractAgentList(payload) {
    if (Array.isArray(payload)) return payload;
    if (payload && Array.isArray(payload.agents)) return payload.agents;
    if (payload && Array.isArray(payload.registered_agents)) return payload.registered_agents;
    if (payload && Array.isArray(payload.local_agents)) return payload.local_agents;
    return [];
}

export function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

export function containsHangul(value) {
    return /[\u3131-\uD79D]/.test(String(value || ''));
}

export function extractJsonArray(value) {
    if (!value) return null;
    try {
        return JSON.parse(value);
    } catch (_) {
        const match = String(value).match(/\[[\s\S]*\]/);
        if (!match) return null;
        try {
            return JSON.parse(match[0]);
        } catch (_) {
            return null;
        }
    }
}

export function formatDuration(seconds) {
    const secs = Math.max(0, Number(seconds) || 0);
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return h > 0 ? `${h}h ${m}m` : `${m}m`;
}

export function formatUptime(secs) {
    if (!secs || secs < 0) return '--';
    if (secs < 3600) return `${Math.floor(secs / 60)}m`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h`;
    return `${Math.floor(secs / 86400)}d`;
}

export function formatMemoryAction(custom) {
    const action = custom?.data?.action;
    if (action === 'core_update') return 'Core Memory Updated';
    if (action === 'tier_add') return 'Memory Added';
    if (action === 'lesson_add') return 'Lesson Published';
    return 'Memory Update';
}

if (typeof window.translateEnabled === 'undefined') {
    window.translateEnabled = true;
}

const translationCache = new Map();
const translationQueue = new Map();
let translationBatchTimer = null;
const translationBatchDelay = 80;

async function requestBatchTranslation(texts) {
    if (!texts.length) return [];
    try {
        const res = await apiFetch(`${API}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: `Translate each Korean text into natural English. Return ONLY a JSON array of strings in the same order.\n\n${JSON.stringify(texts)}`
            }),
        });
        if (!res.ok) throw new Error(`chat ${res.status}`);
        const data = await res.json();
        const parsed = extractJsonArray(data.message);
        if (Array.isArray(parsed)) {
            return parsed.map((value, idx) => (typeof value === 'string' ? value : texts[idx]));
        }
        return texts;
    } catch (_) {
        return texts;
    }
}

async function flushTranslationBatch() {
    translationBatchTimer = null;
    const batch = Array.from(translationQueue.entries());
    translationQueue.clear();
    if (batch.length === 0) return;

    const texts = batch.map(([text]) => text);
    const chunkSize = 20;
    const results = new Array(texts.length);
    for (let i = 0; i < texts.length; i += chunkSize) {
        const slice = texts.slice(i, i + chunkSize);
        const translated = await requestBatchTranslation(slice);
        translated.forEach((value, idx) => {
            results[i + idx] = value ?? slice[idx];
        });
    }

    batch.forEach(([text, entry], idx) => {
        const finalText = results[idx] ?? text;
        const resolved = Promise.resolve(finalText);
        translationCache.set(text, resolved);
        entry.resolvers.forEach(resolve => resolve(finalText));
    });
}

function scheduleTranslationBatch() {
    if (translationBatchTimer) return;
    translationBatchTimer = setTimeout(flushTranslationBatch, translationBatchDelay);
}

function queueTranslation(text) {
    if (translationCache.has(text)) return translationCache.get(text);
    const task = new Promise(resolve => {
        const entry = translationQueue.get(text) || { resolvers: [] };
        entry.resolvers.push(resolve);
        translationQueue.set(text, entry);
    });
    translationCache.set(text, task);
    scheduleTranslationBatch();
    return task;
}

export async function translateToEnglish(text) {
    if (!window.translateEnabled) return text;
    if (!text) return text;
    if (!containsHangul(text)) return text;
    return queueTranslation(text);
}

export function setTranslatedText(el, text) {
    if (!el) return;
    const src = String(text ?? '');
    el.dataset.sourceText = src;
    el.textContent = src;
    translateToEnglish(src).then(result => {
        if (el.dataset.sourceText === src) {
            el.textContent = result;
        }
    });
}
