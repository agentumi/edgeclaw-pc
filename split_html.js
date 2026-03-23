const fs = require('fs');
const path = require('path');

const htmlFile = path.join(__dirname, 'static/dashboard.html');
const newHtmlFile = path.join(__dirname, 'static/dashboard_new.html');
const viewsDir = path.join(__dirname, 'static/views');

const html = fs.readFileSync(htmlFile, 'utf8');

if (!fs.existsSync(viewsDir)) {
  fs.mkdirSync(viewsDir, { recursive: true });
}

const viewsToExtract = [
  'view-dashboard',
  'view-aichat',
  'view-chat',
  'view-fleet',
  'view-board',
  'view-memory',
  'view-market',
  'view-automations',
  'view-extensions',
  'view-settings'
];

let remainingHtml = html;

// Use regex to locate each view div. We know they look like `<div id="view-X" class="view-content...">...</div>`
// and usually end right before the next `<!-- VIEW ` or `<!-- Modals`
for (const id of viewsToExtract) {
  // Find start
  const startStr = `id="${id}"`;
  const startIdx = remainingHtml.indexOf(startStr);
  if (startIdx === -1) continue;
  
  // Find actual element start
  const divStart = remainingHtml.lastIndexOf('<div', startIdx);
  
  // Find end (next view comment or modals comment)
  const nextViewMatch = remainingHtml.slice(divStart + 1).search(/(<!-- VIEW|<!-- Modals)/);
  
  let endIdx;
  if (nextViewMatch !== -1) {
    endIdx = divStart + 1 + nextViewMatch;
  } else {
    // try to find just `</div>` right before end
    endIdx = remainingHtml.length;
  }
  
  const content = remainingHtml.slice(divStart, endIdx);
  
  // Save content
  const filename = id.replace('view-', '') + '.html';
  fs.writeFileSync(path.join(viewsDir, filename), content.trim());
  console.log(`Extracted: ${filename}`);
  
  remainingHtml = remainingHtml.substring(0, divStart) + `<div id="${id}" class="view-content" ${id === 'view-dashboard' ? 'class="view-content active"' : ''}></div>\n` + remainingHtml.substring(endIdx);
}

// Extract modals
const modalsStartMatch = remainingHtml.match(/<!-- Modals -->/);
if (modalsStartMatch) {
    const modalsStart = modalsStartMatch.index;
    const bodyEnd = remainingHtml.lastIndexOf('</body>');
    const modalsContent = remainingHtml.slice(modalsStart, bodyEnd);
    fs.writeFileSync(path.join(viewsDir, 'modals.html'), modalsContent.trim());
    console.log('Extracted: modals.html');
    
    // Replace with a container for modals
    remainingHtml = remainingHtml.substring(0, modalsStart) + '<div id="modals-container"></div>\n' + remainingHtml.substring(bodyEnd);
}

fs.writeFileSync(newHtmlFile, remainingHtml.trim() + '\n</html>');
console.log('Finished splitting HTML!');
