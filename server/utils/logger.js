/**
 * Lightweight Logger Utility
 * Reduces logging overhead in production while keeping debug info in development
 * 
 * Usage:
 *   const logger = require('./utils/logger');
 *   logger.info('Server started');
 *   logger.debug('Detailed info'); // Only in development
 *   logger.error('Something failed', error);
 */

const isDev = process.env.NODE_ENV !== 'production';
const isVerbose = process.env.VERBOSE_LOGGING === 'true';

// Cache timestamp to reduce Date object creation
let lastTimestamp = '';
let lastTime = 0;

function getTimestamp() {
    const now = Date.now();
    if (now - lastTime > 1000) {
        lastTimestamp = new Date().toISOString().slice(11, 19);
        lastTime = now;
    }
    return lastTimestamp;
}

const logger = {
    // Always log
    info: (message, ...args) => {
        console.log(`[${getTimestamp()}] ${message}`, ...args);
    },

    // Only in development or when verbose
    debug: (message, ...args) => {
        if (isDev || isVerbose) {
            console.log(`[${getTimestamp()}] [DEBUG] ${message}`, ...args);
        }
    },

    // Always log warnings
    warn: (message, ...args) => {
        console.warn(`[${getTimestamp()}] [WARN] ${message}`, ...args);
    },

    // Always log errors
    error: (message, ...args) => {
        console.error(`[${getTimestamp()}] [ERROR] ${message}`, ...args);
    },

    // Verbose only - for very detailed tracing
    trace: (message, ...args) => {
        if (isVerbose) {
            console.log(`[${getTimestamp()}] [TRACE] ${message}`, ...args);
        }
    },

    // System messages - startup, shutdown
    system: (message, ...args) => {
        console.log(`[${getTimestamp()}] [SYSTEM] ${message}`, ...args);
    }
};

module.exports = logger;
