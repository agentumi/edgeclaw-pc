const fs = require('fs');
const code = fs.readFileSync('static/js/dashboard/index.js', 'utf8');
const match = code.match(/Object\.assign\(window,\s*\{([^}]+)\}\)/);
if (!match) {
    console.log('No Object.assign block found');
    process.exit(0);
}
const fns = match[1].split(',').map(s=>s.trim()).filter(Boolean);
const defined = [];
const missing = [];
for (const f of fns) {
    if (new RegExp('function\\s+'+f+'\\b').test(code) || new RegExp('(const|let|var)\\s+'+f+'\\s*=').test(code) || code.includes('import { '+f+' }') || code.includes('import { '+f+', ') || code.includes(', '+f+' }') || code.includes('import { '+f+' as')) {
        defined.push(f);
    } else {
        missing.push(f);
    }
}
console.log('Defined:', defined.join(', '));
console.log('---');
console.log('Missing:', missing.join(', '));
