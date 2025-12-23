const http = require('http');

const check = (path) => {
    http.get(`http://localhost:3000${path}`, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            console.log(`\n--- ${path} ---`);
            try {
                const json = JSON.parse(data);
                console.log(JSON.stringify(json, null, 2).substring(0, 500)); // Print first 500 chars
            } catch (e) {
                console.log("Invalid JSON:", data);
            }
        });
    });
};

check('/models');
check('/patterns');
