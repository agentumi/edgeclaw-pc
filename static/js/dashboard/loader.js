async function loadHtmlComponents() {
    const viewFiles = [
        'dashboard',
        'aichat',
        'chat',
        'fleet',
        'board',
        'memory',
        'market',
        'automations',
        'extensions',
        'settings'
    ];

    console.log('Starting HTML component load...');

    try {
        // 1. Load View Partials (Replace placeholders with outerHTML)
        await Promise.all(viewFiles.map(async (view) => {
            try {
                const res = await fetch(`views/${view}.html`);
                if (res.ok) {
                    const html = await res.text();
                    const el = document.getElementById(`view-${view}`);
                    if (el) {
                        el.outerHTML = html;
                        console.log(`- Loaded view: ${view}`);
                    } else {
                        console.warn(`- Placeholder #view-${view} not found for injection`);
                    }
                } else {
                    console.error(`- Failed to fetch views/${view}.html (Status: ${res.status})`);
                    const el = document.getElementById(`view-${view}`);
                    if (el) {
                        el.outerHTML = `<div id="view-${view}" style="padding: 20px; color: var(--accent-red);">Failed to fetch view: ${view}</div>`;
                    }
                }
            } catch (err) {
                console.error(`- Error loading view ${view}:`, err);
            }
        }));

        // 2. Load Modals (Inject into container with innerHTML)
        try {
            const modalsRes = await fetch('views/modals.html');
            if (modalsRes.ok) {
                const modalsHtml = await modalsRes.text();
                const container = document.getElementById('modal-container');
                if (container) {
                    container.innerHTML = modalsHtml;
                    console.log('- Loaded modals.html');
                } else {
                    console.warn('- Placeholder #modal-container not found for injection');
                }
            } else {
                console.error(`- Failed to fetch views/modals.html (Status: ${modalsRes.status})`);
            }
        } catch (err) {
            console.error('- Error loading modals:', err);
        }
        
        console.log(`Successfully completed HTML component load (${viewFiles.length} views processed)`);
    } catch (error) {
        console.error('Critical orchestrator error in loadHtmlComponents:', error);
        throw error;
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    // 1. Load HTML Partials completely
    await loadHtmlComponents();
    
    // 2. Load the main JavaScript orchestrator once the DOM is ready
    await import('./index.js');
});
