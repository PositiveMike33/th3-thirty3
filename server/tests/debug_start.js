// Debug script to capture exact error
process.on('uncaughtException', (e) => {
    console.error('=== UNCAUGHT EXCEPTION ===');
    console.error(e.message);
    console.error(e.stack);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('=== UNHANDLED REJECTION ===');
    console.error('Reason:', reason);
    process.exit(1);
});

require('dotenv').config();
require('./index.js');
