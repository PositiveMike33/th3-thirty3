const http = require('http');

const endpoints = [
    '/sessions',
    '/patterns',
    '/models',
    '/settings',
    '/osint/tools',
    '/projects',
    '/google/status'
];

const checkEndpoint = (path) => {
    return new Promise((resolve) => {
        http.get(`http://localhost:3000${path}`, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        JSON.parse(data);
                        console.log(`✅ ${path}: OK`);
                        resolve(true);
                    } catch (e) {
                        console.log(`❌ ${path}: Invalid JSON`);
                        resolve(false);
                    }
                } else {
                    console.log(`❌ ${path}: Status ${res.statusCode}`);
                    resolve(false);
                }
            });
        }).on('error', (err) => {
            console.log(`❌ ${path}: Connection Error (${err.message})`);
            resolve(false);
        });
    });
};

const run = async () => {
    console.log("🔍 Verifying API Routes...");
    let success = true;
    for (const ep of endpoints) {
        const result = await checkEndpoint(ep);
        if (!result) success = false;
    }

    if (success) {
        console.log("\n✨ All routes verified successfully.");
        process.exit(0);
    } else {
        console.error("\n⚠️ Some routes failed.");
        process.exit(1);
    }
};

run();
