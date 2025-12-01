const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid'); // Need to install uuid or use simple random

class SessionManager {
    constructor() {
        this.sessionsDir = path.join(__dirname, 'sessions');
        if (!fs.existsSync(this.sessionsDir)) {
            fs.mkdirSync(this.sessionsDir);
        }
    }

    // List all sessions (sorted by recent)
    listSessions() {
        const files = fs.readdirSync(this.sessionsDir).filter(f => f.endsWith('.json'));
        const sessions = files.map(file => {
            const filePath = path.join(this.sessionsDir, file);
            const data = JSON.parse(fs.readFileSync(filePath));
            const stats = fs.statSync(filePath);
            return {
                id: file.replace('.json', ''),
                title: data.title || "Nouvelle conversation",
                lastModified: stats.mtime,
                preview: data.messages.length > 1 ? data.messages[data.messages.length - 1].content.substring(0, 50) + "..." : "Vide"
            };
        });
        return sessions.sort((a, b) => b.lastModified - a.lastModified);
    }

    // Get a specific session
    getSession(id) {
        const filePath = path.join(this.sessionsDir, `${id}.json`);
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath));
    }

    // Create a new session
    createSession(title = "Nouvelle conversation") {
        const id = uuidv4(); // Robust UUID
        const session = {
            id,
            title,
            messages: [
                { id: uuidv4(), role: "assistant", content: "Session initialisée. On attaque quoi ?" }
            ]
        };
        this.saveSession(id, session);
        return session;
    }

    // Save a session
    saveSession(id, data) {
        const filePath = path.join(this.sessionsDir, `${id}.json`);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
    }

    // Delete a session
    deleteSession(id) {
        const filePath = path.join(this.sessionsDir, `${id}.json`);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            return true;
        }
        return false;
    }

    // Delete a specific message from a session
    deleteMessage(sessionId, messageId) {
        const session = this.getSession(sessionId);
        if (!session) return false;

        const initialLength = session.messages.length;
        session.messages = session.messages.filter(m => m.id !== messageId);

        if (session.messages.length < initialLength) {
            this.saveSession(sessionId, session);
            return true;
        }
        return false;
    }
}

module.exports = SessionManager;
