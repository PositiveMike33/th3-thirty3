const fs = require('fs');
const path = require('path');

try {
    const content = fs.readFileSync(path.join(__dirname, 'server', 'credentials.json'), 'utf8');
    const creds = JSON.parse(content);
    console.log('--- CREDENTIALS DEBUG ---');
    console.log(JSON.stringify(creds, null, 2));

    const web = creds.web || creds.installed;
    console.log('\n--- REDIRECT URIS ---');
    if (web && web.redirect_uris) {
        web.redirect_uris.forEach((uri, i) => console.log(`URI [${i}]: ${uri}`));
    } else {
        console.log('NO REDIRECT URIS FOUND!');
    }
} catch (e) {
    console.error('ERROR:', e.message);
}
