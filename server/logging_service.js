/**
 * Centralized Logging Service
 * Provides structured logging for all server components
 */

const fs = require('fs');
const path = require('path');

class LoggingService {
    constructor() {
        this.logDir = path.join(__dirname, 'logs');
        this.ensureLogDir();

        // Log levels
        this.LEVELS = {
            DEBUG: 0,
            INFO: 1,
            WARN: 2,
            ERROR: 3
        };

        this.currentLevel = process.env.LOG_LEVEL ?
            this.LEVELS[process.env.LOG_LEVEL.toUpperCase()] || 1 : 1;
    }

    ensureLogDir() {
        if (!fs.existsSync(this.logDir)) {
            fs.mkdirSync(this.logDir, { recursive: true });
        }
    }

    getTimestamp() {
        return new Date().toISOString();
    }

    getLogFilename() {
        const date = new Date().toISOString().split('T')[0];
        return path.join(this.logDir, `nexus33-${date}.log`);
    }

    formatMessage(level, component, message, data = null) {
        const entry = {
            timestamp: this.getTimestamp(),
            level,
            component,
            message,
            ...(data && { data })
        };
        return JSON.stringify(entry);
    }

    write(level, component, message, data = null) {
        if (this.LEVELS[level] < this.currentLevel) return;

        const formatted = this.formatMessage(level, component, message, data);

        // Console output with colors
        const colors = {
            DEBUG: '\x1b[36m',  // Cyan
            INFO: '\x1b[32m',   // Green
            WARN: '\x1b[33m',   // Yellow
            ERROR: '\x1b[31m'   // Red
        };
        const reset = '\x1b[0m';

        console.log(`${colors[level] || ''}[${level}]${reset} [${component}] ${message}`);

        // File output
        try {
            fs.appendFileSync(this.getLogFilename(), formatted + '\n');
        } catch (err) {
            console.error('Failed to write log:', err.message);
        }
    }

    debug(component, message, data) {
        this.write('DEBUG', component, message, data);
    }

    info(component, message, data) {
        this.write('INFO', component, message, data);
    }

    warn(component, message, data) {
        this.write('WARN', component, message, data);
    }

    error(component, message, data) {
        this.write('ERROR', component, message, data);
    }

    // Get recent logs
    getRecentLogs(lines = 100) {
        try {
            const logFile = this.getLogFilename();
            if (!fs.existsSync(logFile)) return [];

            const content = fs.readFileSync(logFile, 'utf8');
            const allLines = content.trim().split('\n');
            return allLines.slice(-lines).map(line => {
                try {
                    return JSON.parse(line);
                } catch {
                    return { raw: line };
                }
            });
        } catch (err) {
            return [{ error: err.message }];
        }
    }

    // Get log stats
    getStats() {
        try {
            const logs = this.getRecentLogs(1000);
            const stats = {
                total: logs.length,
                byLevel: {},
                byComponent: {}
            };

            logs.forEach(log => {
                if (log.level) {
                    stats.byLevel[log.level] = (stats.byLevel[log.level] || 0) + 1;
                }
                if (log.component) {
                    stats.byComponent[log.component] = (stats.byComponent[log.component] || 0) + 1;
                }
            });

            return stats;
        } catch {
            return { total: 0, byLevel: {}, byComponent: {} };
        }
    }
}

// Singleton instance
const logger = new LoggingService();

module.exports = logger;
