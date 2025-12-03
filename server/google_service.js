const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const { OAuth2 } = google.auth;

const SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/drive.readonly',
    'https://www.googleapis.com/auth/tasks'
];

class GoogleService {
    constructor() {
        this.credentialsPath = path.join(__dirname, 'credentials.json');
        this.tokensDir = path.join(__dirname, 'tokens');
        this.clients = {}; // Map<email, OAuth2Client>

        if (!fs.existsSync(this.tokensDir)) {
            fs.mkdirSync(this.tokensDir);
        }
    }

    getAuthUrl(email) {
        if (!fs.existsSync(this.credentialsPath)) {
            throw new Error("Fichier credentials.json manquant !");
        }

        const content = fs.readFileSync(this.credentialsPath);
        const credentials = JSON.parse(content);
        const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;

        const oAuth2Client = new OAuth2(client_id, client_secret, redirect_uris[0]);

        // Store client temporarily to retrieve token later
        this.clients[email] = oAuth2Client;

        return oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
            state: email, // Pass email as state to know which account is authenticating
            prompt: 'consent' // Force consent to ensure we get a refresh_token
        });
    }

    async handleCallback(code, email) {
        if (!this.clients[email]) {
            // Re-instantiate if missing (e.g. server restart during auth)
            this.getAuthUrl(email);
        }

        const oAuth2Client = this.clients[email];
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);

        // Save token
        const tokenPath = path.join(this.tokensDir, `token_${email}.json`);
        fs.writeFileSync(tokenPath, JSON.stringify(tokens));
        console.log(`[GOOGLE] Token stored for ${email}`);

        return true;
    }

    async getClient(email) {
        const tokenPath = path.join(this.tokensDir, `token_${email}.json`);
        if (!fs.existsSync(tokenPath)) return null;

        if (!fs.existsSync(this.credentialsPath)) return null;

        const content = fs.readFileSync(this.credentialsPath);
        const credentials = JSON.parse(content);
        const { client_secret, client_id, redirect_uris } = credentials.installed || credentials.web;

        const oAuth2Client = new OAuth2(client_id, client_secret, redirect_uris[0]);
        const tokens = JSON.parse(fs.readFileSync(tokenPath));
        oAuth2Client.setCredentials(tokens);

        return oAuth2Client;
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
}

module.exports = GoogleService;
