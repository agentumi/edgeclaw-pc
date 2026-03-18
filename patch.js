const fs = require('fs');
const file = 'static/js/dashboard/index.js';
let code = fs.readFileSync(file, 'utf8');

const match = code.match(/Object\.assign\(window,\s*\{([\s\S]+?)\}\)/);
if (match) {
    const fns = match[1].split(',').map(s=>s.trim()).filter(Boolean);
    console.log('Found ' + fns.length + ' functions to export.');

    // We will replace `Object.assign(window, { ... })` with a loop that checks `typeof`, but since
    // they are local variables, we must reference them directly. Wait, if we use a safe syntax:
    // `if (typeof funcName !== "undefined") window.funcName = funcName;`
    // We can generate that!

    let replacement = '';
    for (const f of fns) {
        // Skip comments like `// AppState Subscribers`
        if (f.startsWith('//')) {
             replacement += '    ' + f + '\n';
             continue;
        }
        replacement += `    if (typeof ${f} !== 'undefined') window.${f} = ${f};\n`;
    }

    code = code.replace(match[0], replacement);
    fs.writeFileSync(file, code);
    console.log('Patched Object.assign block!');
} else {
    console.log('Block not found');
}
