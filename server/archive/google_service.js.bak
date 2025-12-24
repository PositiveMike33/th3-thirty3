const fs = require('fs');
const path = require('path');

// LAZY LOAD: googleapis is 189MB - only load when needed
let google = null;
let OAuth2 = null;

const SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/tasks'
];

// Lazy load function
function loadGoogleApis() {
    if (!google) {
        const googleapis = require('googleapis');
        google = googleapis.google;
        OAuth2 = google.auth.OAuth2;
        console.log("[GOOGLE] googleapis loaded (189MB)");
    }
    return { google, OAuth2 };
}

class GoogleService {
    constructor() {
        this.credentialsPath = path.join(__dirname, 'credentials.json');
        this.tokensDir = path.join(__dirname, 'tokens');
        this.clients = {}; // Map<email, OAuth2Client>
        this.credentials = null;
        this.isAvailable = false;

        if (!fs.existsSync(this.tokensDir)) {
            fs.mkdirSync(this.tokensDir);
        }

        // Load credentials once - but don't load googleapis yet
        if (fs.existsSync(this.credentialsPath)) {
            try {
                const content = fs.readFileSync(this.credentialsPath);
                this.credentials = JSON.parse(content);
                this.isAvailable = true;
                console.log("[GOOGLE] Credentials found - googleapis will load on first use");
            } catch (e) {
                console.error("[GOOGLE] Failed to load credentials.json:", e.message);
            }
        } else {
            console.log("[GOOGLE] No credentials.json - 189MB googleapis skipped");
        }
    }


    getAuthUrl(email) {
        if (!this.credentials) {
            throw new Error("Fichier credentials.json manquant ou invalide !");
        }

        // Lazy load googleapis on first use
        const { OAuth2: OAuth2Client } = loadGoogleApis();

        const { client_secret, client_id, redirect_uris } = this.credentials.installed || this.credentials.web;
        const oAuth2Client = new OAuth2Client(client_id, client_secret, redirect_uris[0]);

        // Store client temporarily
        this.clients[email] = oAuth2Client;

        return oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
            state: email,
            prompt: 'consent'
        });
    }


    async handleCallback(code, email) {
        if (!this.clients[email]) {
            this.getAuthUrl(email);
        }

        const oAuth2Client = this.clients[email];
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);

        // Save token async
        const tokenPath = path.join(this.tokensDir, `token_${email}.json`);
        await require('fs').promises.writeFile(tokenPath, JSON.stringify(tokens));
        console.log(`[GOOGLE] Token stored for ${email}`);

        return true;
    }

    async getClient(email) {
        // Return cached client if credentials are valid and not expired
        if (this.clients[email] && this.clients[email].credentials) {
            const tokens = this.clients[email].credentials;
            const now = Date.now();
            
            // Check if token is expired (with 5 min buffer)
            if (tokens.expiry_date && tokens.expiry_date > now + 300000) {
                return this.clients[email];
            }
        }

        const tokenPath = path.join(this.tokensDir, `token_${email}.json`);
        if (!fs.existsSync(tokenPath)) return null;
        if (!this.credentials) return null;

        // Lazy load googleapis
        const { OAuth2: OAuth2Client } = loadGoogleApis();

        const { client_secret, client_id, redirect_uris } = this.credentials.installed || this.credentials.web;
        const oAuth2Client = new OAuth2Client(client_id, client_secret, redirect_uris[0]);

        try {
            const tokenContent = await require('fs').promises.readFile(tokenPath, 'utf8');
            const tokens = JSON.parse(tokenContent);
            oAuth2Client.setCredentials(tokens);

            // Check if token needs refresh
            if (tokens.refresh_token && tokens.expiry_date && tokens.expiry_date < Date.now()) {
                console.log(`[GOOGLE] Token expired for ${email}, refreshing...`);
                try {
                    const { credentials: newTokens } = await oAuth2Client.refreshAccessToken();
                    oAuth2Client.setCredentials(newTokens);
                    
                    // Save refreshed token
                    const updatedTokens = { ...tokens, ...newTokens };
                    await require('fs').promises.writeFile(tokenPath, JSON.stringify(updatedTokens));
                    console.log(`[GOOGLE] Token refreshed for ${email}`);
                } catch (refreshError) {
                    console.error(`[GOOGLE] Token refresh failed for ${email}:`, refreshError.message);
                    // Token is invalid, needs re-auth
                    return null;
                }
            }

            // Cache the client
            this.clients[email] = oAuth2Client;
            return oAuth2Client;
        } catch (e) {
            console.error(`[GOOGLE] Failed to load token for ${email}:`, e.message);
            return null;
        }
    }

    async listUnreadEmails(email) {
        const messages = await this.getUnreadEmails(email);
        if (!messages || messages.length === 0) return "Aucun email non lu.";

        let summary = "";
        messages.forEach(msg => {
            summary += `- De: ${msg.from} | Sujet: ${msg.subject}\n`;
        });
        return summary;
    }

    async getUnreadEmails(email) {
        const auth = await this.getClient(email);
        if (!auth) return [];

        const gmail = google.gmail({ version: 'v1', auth });
        try {
            const res = await gmail.users.messages.list({
                userId: 'me',
                q: 'is:unread',
                maxResults: 10
            });

            const messages = res.data.messages;
            if (!messages || messages.length === 0) return [];

            const emailData = [];
            for (const message of messages) {
                const msg = await gmail.users.messages.get({
                    userId: 'me',
                    id: message.id
                });
                const headers = msg.data.payload.headers;
                const subject = headers.find(h => h.name === 'Subject')?.value || '(Sans sujet)';
                const from = headers.find(h => h.name === 'From')?.value || '(Inconnu)';
                const date = headers.find(h => h.name === 'Date')?.value;

                emailData.push({
                    id: message.id,
                    subject,
                    from,
                    date,
                    snippet: msg.data.snippet
                });
            }
            return emailData;
        } catch (error) {
            console.error(`Error fetching emails for ${email}:`, error);
            return [];
        }
    }

    async listUpcomingEvents(email) {
        const events = await this.getUpcomingEvents(email);
        if (!events || events.length === 0) return "Aucun événement à venir.";

        let summary = "";
        events.forEach(event => {
            const start = event.start.dateTime || event.start.date;
            summary += `- ${start} : ${event.summary}\n`;
        });
        return summary;
    }

    async getUpcomingEvents(email) {
        const auth = await this.getClient(email);
        if (!auth) return [];

        const calendar = google.calendar({ version: 'v3', auth });
        try {
            const res = await calendar.events.list({
                calendarId: 'primary',
                timeMin: (new Date()).toISOString(),
                maxResults: 10,
                singleEvents: true,
                orderBy: 'startTime',
            });
            return res.data.items || [];
        } catch (error) {
            console.error(`Error fetching calendar for ${email}:`, error);
            return [];
        }
    }

    async listTasks(email) {
        const tasks = await this.getTasks(email);
        if (!tasks || tasks.length === 0) return "Aucune tâche à faire.";

        let summary = "";
        tasks.forEach(t => {
            summary += `- [ ] ${t.title} (Due: ${t.due ? t.due.split('T')[0] : 'Pas de date'})\n`;
        });
        return summary;
    }

    async getTasks(email) {
        const auth = await this.getClient(email);
        if (!auth) return [];

        const service = google.tasks({ version: 'v1', auth });
        try {
            const taskLists = await service.tasklists.list({ maxResults: 1 });
            if (!taskLists.data.items || taskLists.data.items.length === 0) return [];

            const taskListId = taskLists.data.items[0].id;
            const res = await service.tasks.list({
                tasklist: taskListId,
                maxResults: 10,
                showCompleted: false
            });
            return res.data.items || [];
        } catch (error) {
            console.error(`Error fetching tasks for ${email}:`, error);
            return [];
        }
    }

    async listDriveFiles(email) {
        const files = await this.getDriveFiles(email);
        if (!files || files.length === 0) return "Aucun fichier récent.";

        let summary = "";
        files.forEach(f => {
            summary += `- [${f.mimeType.split('/').pop()}] ${f.name} (Modifié: ${f.modifiedTime})\n`;
        });
        return summary;
    }

    async getDriveFiles(email) {
        const auth = await this.getClient(email);
        if (!auth) return [];

        const drive = google.drive({ version: 'v3', auth });
        try {
            const res = await drive.files.list({
                pageSize: 10,
                fields: 'nextPageToken, files(id, name, mimeType, modifiedTime, webViewLink)',
                orderBy: 'modifiedTime desc'
            });
            return res.data.files || [];
        } catch (error) {
            console.error(`Error fetching drive files for ${email}:`, error);
            return [];
        }
    }
    async archiveEmail(email, messageId) {
        const auth = await this.getClient(email);
        if (!auth) return false;

        const gmail = google.gmail({ version: 'v1', auth });
        try {
            await gmail.users.messages.modify({
                userId: 'me',
                id: messageId,
                requestBody: {
                    removeLabelIds: ['INBOX']
                }
            });
            return true;
        } catch (error) {
            console.error(`Error archiving email ${messageId} for ${email}:`, error);
            return false;
        }
    }

    /**
     * Complete (or uncomplete) a task in Google Tasks
     * @param {string} email - User email
     * @param {string} taskId - The ID of the task to complete
     * @param {boolean} completed - Whether to mark as completed (true) or uncomplete (false)
     */
    async completeTask(email, taskId, completed = true) {
        const auth = await this.getClient(email);
        if (!auth) return { success: false, error: 'Not authenticated' };

        const service = google.tasks({ version: 'v1', auth });
        try {
            // First, get the default task list
            const taskLists = await service.tasklists.list({ maxResults: 1 });
            if (!taskLists.data.items || taskLists.data.items.length === 0) {
                return { success: false, error: 'No task lists found' };
            }

            const taskListId = taskLists.data.items[0].id;

            // Update the task status
            const result = await service.tasks.patch({
                tasklist: taskListId,
                task: taskId,
                requestBody: {
                    status: completed ? 'completed' : 'needsAction',
                    ...(completed ? { completed: new Date().toISOString() } : { completed: null })
                }
            });

            console.log(`[GOOGLE] Task ${taskId} marked as ${completed ? 'completed' : 'active'} for ${email}`);
            return { success: true, task: result.data };
        } catch (error) {
            console.error(`Error updating task ${taskId} for ${email}:`, error);
            return { success: false, error: error.message };
        }
    }
}

module.exports = GoogleService;
