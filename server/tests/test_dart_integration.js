
const DartService = require('./dart_service');

async function testDartReal() {
    console.log("=== TRYING TO CONNECT TO DART AI (REAL) ===");
    const dart = new DartService();

    // Authenticate
    try {
        console.log("Authenticating...");
        await dart.authenticate();
        console.log("✅ Auth Success!");
    } catch (e) {
        console.error("❌ Auth Failed:", e.message);
        return;
    }

    // List Tasks
    try {
        console.log("\nListing tasks...");
        const tasks = await dart.listTasks();
        if (tasks.success) {
            console.log("✅ Tasks retrieved:");
            console.log(tasks.output);
        } else {
            console.error("❌ List Tasks Failed:", tasks.error);
        }
    } catch (e) {
        console.error("❌ List Tasks Error:", e.message);
    }
}

testDartReal();
