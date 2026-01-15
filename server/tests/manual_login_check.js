
const http = require('http');

console.log("Testing Login with reset credentials...");

const data = JSON.stringify({
    email: 'th3thirty3@gmail.com',
    password: 'Buthaijutsu333!'
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/auth/login',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': data.length
    }
};

const req = http.request(options, (res) => {
    let responseBody = '';

    res.on('data', (chunk) => {
        responseBody += chunk;
    });

    res.on('end', () => {
        console.log(`Status Code: ${res.statusCode}`);
        try {
            const json = JSON.parse(responseBody);
            if (json.success) {
                console.log("✅ Login Successful!");
                console.log("Token received:", json.token ? "YES" : "NO");
                console.log("User:", json.user ? json.user.username : "Unknown");
            } else {
                console.log("❌ Login Failed.");
                console.log("Error:", json.error);
            }
        } catch (e) {
            console.log("Response (Raw):", responseBody);
        }
    });
});

req.on('error', (error) => {
    console.error("❌ Request Error:", error.message);
});

req.write(data);
req.end();
