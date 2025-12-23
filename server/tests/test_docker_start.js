const OsintService = require('./osint_service');

async function testDockerStart() {
    console.log("Testing Docker Auto-start...");
    const osint = new OsintService();

    // The constructor calls ensureDockerRunning, but it's async and not awaited in constructor.
    // We can call it explicitly here to wait for it.
    await osint.ensureDockerRunning();

    console.log("Docker check completed.");
}

testDockerStart();
