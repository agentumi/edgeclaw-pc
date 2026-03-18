const fs = require('fs');
const code = fs.readFileSync('static/js/dashboard/index.js', 'utf8');

function isDefined(name) {
    const regexes = [
        new RegExp('function\\s+' + name + '\\b'),
        new RegExp('(const|let|var)\\s+' + name + '\\s*='),
        new RegExp('import\\s+.*' + name + '.*\\s+from'),
        new RegExp('window\\.' + name + '\\s*=')
    ];
    return regexes.some(r => r.test(code));
}

const calls = [
    'initChat',
    'initDevAutoReload',
    'fetchStatus',
    'fetchTasks',
    'fetchMemory',
    'updateContextPanel',
    'ensureSpaRoute',
    'activateViewFromHash',
    'renderExtGrid',
    'updateExtCatCounts'
];

console.log('--- Initialization Calls Check ---');
for (const c of calls) {
    if (isDefined(c)) {
        console.log('[OK] ' + c + ' is defined');
    } else {
        console.log('[MISSING] ' + c + ' is NOT defined');
    }
}
