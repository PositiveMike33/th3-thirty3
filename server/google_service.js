const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');
const { OAuth2 } = google.auth;
const User = require('./models/User');

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
        this.credentialsPath = path.join(__dirname, 'credentials.json');
        // this.tokensDir = path.join(__dirname, 'tokens'); // DEPRECATED: Stored in MongoDB
        this.clients = {}; // Map<email, OAuth2Client>
        this.credentials = null;

        // if (!fs.existsSync(this.tokensDir)) {
        //     fs.mkdirSync(this.tokensDir);
        // }

        // Load credentials once
        if (fs.existsSync(this.credentialsPath)) {
            try {
                const content = fs.readFileSync(this.credentialsPath);
                this.credentials = JSON.parse(content);
            } catch (e) {
                console.error("[GOOGLE] Failed to load credentials.json:", e.message);
            }
        }
    }

    getAuthUrl(email) {
        if (!this.credentials) {
            throw new Error("Fichier credentials.json manquant ou invalide !");
        }

        const { client_secret, client_id } = this.credentials.installed || this.credentials.web;
        // FORCE CORRECT REDIRECT URI for Localhost Development
        const redirectUri = 'http://localhost:3000/auth/google/callback';

        console.log(`[GOOGLE] Generating Auth URL for ${email} with redirect: ${redirectUri}`);

        const oAuth2Client = new OAuth2(client_id, client_secret, redirectUri);

        // Store client temporarily
        this.clients[email] = oAuth2Client;

        return oAuth2Client.generateAuthUrl({
            access_type: 'offline', // OBLIGATOIRE pour avoir le refresh_token
            scope: SCOPES,
            state: email,
            prompt: 'consent' // Force la génération du refresh_token même si déjà autorisé
        });
    }

    async handleCallback(code, email) {
        console.log(`[GOOGLE] Handling callback for ${email} with code: ${code.substring(0, 10)}...`);

        if (!this.clients[email]) {
            console.log(`[GOOGLE] No client found for ${email}, regenerating...`);
            this.getAuthUrl(email); // Re-init client
        }

        const oAuth2Client = this.clients[email];
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);

        // Save token to MongoDB
        try {
            await User.findOneAndUpdate(
                { email: email },
                { $set: { googleTokens: tokens } },
                { upsert: true, new: true }
            );
            console.log(`[GOOGLE] Token stored in DB for ${email}`);
        } catch (err) {
            console.error(`[GOOGLE] Failed to save token to DB for ${email}:`, err);
        }

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

        if (!this.credentials) {
            console.error('[GOOGLE] getClient: Credentials not loaded.');
            return null;
        }

        // Fetch from MongoDB
        const user = await User.findOne({ email });
        if (!user) {
            console.warn(`[GOOGLE] getClient: User not found in DB for ${email}`);
            return null;
        }
        if (!user.googleTokens) {
            console.warn(`[GOOGLE] getClient: No tokens found in DB for ${email}`);
            return null;
        }

        const { client_secret, client_id, redirect_uris } = this.credentials.installed || this.credentials.web;
        const oAuth2Client = new OAuth2(client_id, client_secret, redirect_uris[0]);

        try {
            const tokens = user.googleTokens;
            oAuth2Client.setCredentials(tokens);

            // Check if token needs refresh
            if (tokens.refresh_token && tokens.expiry_date && tokens.expiry_date < Date.now()) {
                console.log(`[GOOGLE] Token expired for ${email}, refreshing...`);
                try {
                    const { credentials: newTokens } = await oAuth2Client.refreshAccessToken();
                    oAuth2Client.setCredentials(newTokens);

                    // Save refreshed token to DB
                    const updatedTokens = { ...tokens, ...newTokens };
                    await User.findOneAndUpdate(
                        { email },
                        { $set: { googleTokens: updatedTokens } }
                    );
                    console.log(`[GOOGLE] Token refreshed and saved for ${email}`);
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

    /**
     * Centralized request execution with 401 retry logic
     */
    async _executeWithRetry(email, apiCallFn) {
        try {
            // First attempt
            const auth = await this.getClient(email);
            if (!auth) throw new Error("Authentification impossible (token manquant ou expiré)");
            return await apiCallFn(auth);
        } catch (error) {
            // Check if error is 401 (Unauthorized) or 400 with "invalid_grant"
            const isAuthError = error.code === 401 ||
                (error.response && error.response.status === 401) ||
                (error.message && error.message.includes('invalid_grant'));

            if (isAuthError) {
                console.log(`[GOOGLE] Auth error detected for ${email}. Forcing token refresh...`);

                // 1. Invalidate memory cache
                if (this.clients[email]) {
                    delete this.clients[email];
                }

                // 2. Force refresh via getClient (it will see no cache and load from DB/Refresh)
                // We might need to force a refresh even if DB says it's valid if it was revoked
                const user = await User.findOne({ email });
                if (user && user.googleTokens && user.googleTokens.refresh_token) {
                    try {
                        const { client_secret, client_id, redirect_uris } = this.credentials.installed || this.credentials.web;
                        const oAuth2Client = new OAuth2(client_id, client_secret, redirect_uris[0]);
                        oAuth2Client.setCredentials(user.googleTokens);

                        console.log(`[GOOGLE] Attempting hard refresh for ${email}...`);
                        const { credentials } = await oAuth2Client.refreshAccessToken();

                        // Update DB
                        const updatedTokens = { ...user.googleTokens, ...credentials };
                        await User.findOneAndUpdate(
                            { email },
                            { $set: { googleTokens: updatedTokens } }
                        );

                        // Update Cache
                        oAuth2Client.setCredentials(updatedTokens);
                        this.clients[email] = oAuth2Client;

                        console.log(`[GOOGLE] Hard refresh successful. Retrying request...`);
                        return await apiCallFn(oAuth2Client);

                    } catch (refreshError) {
                        console.error(`[GOOGLE] Hard refresh failed:`, refreshError.message);
                        throw new Error("Session expirée. Veuillez vous reconnecter via /settings");
                    }
                }
            }
            throw error;
        }
    }

    async listUnreadEmails(email) {
        try {
            const messages = await this.getUnreadEmails(email);
            if (!messages || messages.length === 0) return "Aucun email non lu.";

            let summary = "";
            messages.forEach(msg => {
                summary += `- De: ${msg.from} | Sujet: ${msg.subject}\n`;
            });
            return summary;
        } catch (error) {
            return `Erreur: ${error.message}`;
        }
    }

    async getUnreadEmails(email) {
        return this._executeWithRetry(email, async (auth) => {
            const gmail = google.gmail({ version: 'v1', auth });
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
        });
    }

    async getEmailById(email, messageId) {
        return this._executeWithRetry(email, async (auth) => {
            const gmail = google.gmail({ version: 'v1', auth });
            const msg = await gmail.users.messages.get({
                userId: 'me',
                id: messageId,
                format: 'full'
            });

            const headers = msg.data.payload.headers;
            const subject = headers.find(h => h.name === 'Subject')?.value || '(Sans sujet)';
            const from = headers.find(h => h.name === 'From')?.value || '(Inconnu)';
            const to = headers.find(h => h.name === 'To')?.value || '';
            const date = headers.find(h => h.name === 'Date')?.value;

            // Extract body
            let body = '';
            const payload = msg.data.payload;

            if (payload.body && payload.body.data) {
                body = Buffer.from(payload.body.data, 'base64').toString('utf-8');
            } else if (payload.parts) {
                for (const part of payload.parts) {
                    if (part.mimeType === 'text/html' && part.body.data) {
                        body = Buffer.from(part.body.data, 'base64').toString('utf-8');
                        break;
                    } else if (part.mimeType === 'text/plain' && part.body.data) {
                        body = Buffer.from(part.body.data, 'base64').toString('utf-8');
                    }
                }
            }

            return {
                id: messageId,
                subject,
                from,
                to,
                date,
                snippet: msg.data.snippet,
                body: body,
                labelIds: msg.data.labelIds
            };
        });
    }

    async listUpcomingEvents(email) {
        try {
            const events = await this.getUpcomingEvents(email);
            if (!events || events.length === 0) return "Aucun événement à venir.";

            let summary = "";
            events.forEach(event => {
                const start = event.start.dateTime || event.start.date;
                summary += `- ${start} : ${event.summary}\n`;
            });
            return summary;
        } catch (error) {
            return `Erreur: ${error.message}`;
        }
    }

    async getUpcomingEvents(email) {
        return this._executeWithRetry(email, async (auth) => {
            const calendar = google.calendar({ version: 'v3', auth });
            const res = await calendar.events.list({
                calendarId: 'primary',
                timeMin: (new Date()).toISOString(),
                maxResults: 10,
                singleEvents: true,
                orderBy: 'startTime',
            });
            return res.data.items || [];
        });
    }

    async listTasks(email) {
        try {
            const tasks = await this.getTasks(email);
            if (!tasks || tasks.length === 0) return "Aucune tâche à faire.";

            let summary = "";
            tasks.forEach(t => {
                summary += `- [ ] ${t.title} (Due: ${t.due ? t.due.split('T')[0] : 'Pas de date'})\n`;
            });
            return summary;
        } catch (error) {
            return `Erreur: ${error.message}`;
        }
    }

    async getTasks(email) {
        return this._executeWithRetry(email, async (auth) => {
            const service = google.tasks({ version: 'v1', auth });
            const taskLists = await service.tasklists.list({ maxResults: 1 });
            if (!taskLists.data.items || taskLists.data.items.length === 0) return [];

            const taskListId = taskLists.data.items[0].id;
            const res = await service.tasks.list({
                tasklist: taskListId,
                maxResults: 10,
                showCompleted: false
            });
            return res.data.items || [];
        });
    }

    async listDriveFiles(email) {
        try {
            const files = await this.getDriveFiles(email);
            if (!files || files.length === 0) return "Aucun fichier récent.";

            let summary = "";
            files.forEach(f => {
                summary += `- [${f.mimeType.split('/').pop()}] ${f.name} (Modifié: ${f.modifiedTime})\n`;
            });
            return summary;
        } catch (error) {
            return `Erreur: ${error.message}`;
        }
    }

    async getDriveFiles(email) {
        return this._executeWithRetry(email, async (auth) => {
            const drive = google.drive({ version: 'v3', auth });
            const res = await drive.files.list({
                pageSize: 10,
                fields: 'nextPageToken, files(id, name, mimeType, modifiedTime, webViewLink)',
                orderBy: 'modifiedTime desc'
            });
            return res.data.files || [];
        });
    }

    async archiveEmail(email, messageId) {
        try {
            await this._executeWithRetry(email, async (auth) => {
                const gmail = google.gmail({ version: 'v1', auth });
                await gmail.users.messages.modify({
                    userId: 'me',
                    id: messageId,
                    requestBody: {
                        removeLabelIds: ['INBOX']
                    }
                });
            });
            return true;
        } catch (error) {
            console.error(`Error archiving email ${messageId} for ${email}:`, error);
            return false;
        }
    }
}

module.exports = GoogleService;
