/**
 * Google Multi-Account Service
 * Supports 3 Gmail accounts with Gmail, Calendar, Drive, and YouTube APIs
 * 
 * @author Th3 Thirty3
 * @version 2.0.0
 */
const { google } = require('googleapis');
const fs = require('fs');
const path = require('path');
const EventEmitter = require('events');

class GoogleMultiAccountService extends EventEmitter {
    constructor() {
        super();
        
        // Account configuration
        this.accounts = [
            { email: 'mikegauthierguillet@gmail.com', priority: 1 },
            { email: 'th3thirty3@gmail.com', priority: 2 },
            { email: 'mgauthierguillet@gmail.com', priority: 3 }
        ];
        
        // OAuth2 clients per account
        this.clients = new Map();
        
        // API instances per account
        this.gmailClients = new Map();
        this.calendarClients = new Map();
        this.driveClients = new Map();
        this.youtubeClients = new Map();
        
        // Token storage path
        this.tokensDir = path.join(__dirname, 'data', 'google_tokens');
        
        // OAuth2 credentials from .env
        this.credentials = {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            redirectUri: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:3000/auth/google/callback'
        };
        
        // Scopes needed for all services
        this.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/gmail.send',
            'https://www.googleapis.com/auth/gmail.labels',
            'https://www.googleapis.com/auth/calendar',
            'https://www.googleapis.com/auth/calendar.events',
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/drive.file',
            'https://www.googleapis.com/auth/youtube.readonly',
            'https://www.googleapis.com/auth/youtube'
        ];
        
        // Connection status
        this.status = new Map();
        
        // Ensure tokens directory exists
        if (!fs.existsSync(this.tokensDir)) {
            fs.mkdirSync(this.tokensDir, { recursive: true });
        }
        
        console.log('[GOOGLE] Multi-Account Service initialized (3 accounts, 4 APIs)');
    }

    /**
     * Initialize service and load existing tokens
     */
    async initialize() {
        for (const account of this.accounts) {
            await this.initializeAccount(account.email);
        }
        
        console.log('[GOOGLE] Accounts initialized:', this.accounts.map(a => a.email).join(', '));
        return this.getStatus();
    }

    /**
     * Initialize a single account
     */
    async initializeAccount(email) {
        try {
            // Create OAuth2 client for this account
            const oauth2Client = new google.auth.OAuth2(
                this.credentials.clientId,
                this.credentials.clientSecret,
                this.credentials.redirectUri
            );
            
            this.clients.set(email, oauth2Client);
            
            // Try to load existing token
            const tokenPath = this.getTokenPath(email);
            if (fs.existsSync(tokenPath)) {
                const tokens = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
                oauth2Client.setCredentials(tokens);
                
                // Initialize API clients
                await this.initializeApiClients(email, oauth2Client);
                
                this.status.set(email, { connected: true, lastAuth: new Date().toISOString() });
                console.log(`[GOOGLE] ✅ ${email} connected`);
            } else {
                this.status.set(email, { connected: false, reason: 'No token found' });
                console.log(`[GOOGLE] ⚠️ ${email} needs authorization`);
            }
            
            // Handle token refresh
            oauth2Client.on('tokens', (tokens) => {
                this.saveTokens(email, tokens);
            });
            
        } catch (error) {
            this.status.set(email, { connected: false, error: error.message });
            console.error(`[GOOGLE] ❌ ${email} initialization failed:`, error.message);
        }
    }

    /**
     * Initialize API clients for an account
     */
    async initializeApiClients(email, auth) {
        // Gmail
        this.gmailClients.set(email, google.gmail({ version: 'v1', auth }));
        
        // Calendar
        this.calendarClients.set(email, google.calendar({ version: 'v3', auth }));
        
        // Drive
        this.driveClients.set(email, google.drive({ version: 'v3', auth }));
        
        // YouTube
        this.youtubeClients.set(email, google.youtube({ version: 'v3', auth }));
    }

    /**
     * Get token file path for an account
     */
    getTokenPath(email) {
        const safeEmail = email.replace(/[@.]/g, '_');
        return path.join(this.tokensDir, `${safeEmail}_token.json`);
    }

    /**
     * Save tokens to file
     */
    saveTokens(email, tokens) {
        const tokenPath = this.getTokenPath(email);
        
        // Merge with existing tokens (for refresh)
        let existingTokens = {};
        if (fs.existsSync(tokenPath)) {
            existingTokens = JSON.parse(fs.readFileSync(tokenPath, 'utf8'));
        }
        
        const mergedTokens = { ...existingTokens, ...tokens };
        fs.writeFileSync(tokenPath, JSON.stringify(mergedTokens, null, 2));
        console.log(`[GOOGLE] Tokens saved for ${email}`);
    }

    /**
     * Generate OAuth2 authorization URL for an account
     */
    getAuthUrl(email) {
        const client = this.clients.get(email);
        if (!client) {
            throw new Error(`No client for ${email}`);
        }
        
        return client.generateAuthUrl({
            access_type: 'offline',
            scope: this.scopes,
            prompt: 'consent',
            login_hint: email,
            state: email  // Pass email as state for callback identification
        });
    }

    /**
     * Handle OAuth2 callback and save tokens
     */
    async handleCallback(email, code) {
        const client = this.clients.get(email);
        if (!client) {
            throw new Error(`No client for ${email}`);
        }
        
        const { tokens } = await client.getToken(code);
        client.setCredentials(tokens);
        
        // Save tokens
        this.saveTokens(email, tokens);
        
        // Initialize API clients
        await this.initializeApiClients(email, client);
        
        this.status.set(email, { connected: true, lastAuth: new Date().toISOString() });
        this.emit('connected', { email });
        
        return { success: true, email };
    }

    /**
     * Get overall service status
     */
    getStatus() {
        const accounts = [];
        for (const account of this.accounts) {
            const status = this.status.get(account.email) || { connected: false };
            accounts.push({
                email: account.email,
                priority: account.priority,
                ...status
            });
        }
        
        return {
            service: 'Google Multi-Account Service',
            totalAccounts: this.accounts.length,
            connected: accounts.filter(a => a.connected).length,
            accounts,
            apis: ['gmail', 'calendar', 'drive', 'youtube']
        };
    }

    // ================================================================
    // GMAIL API
    // ================================================================

    /**
     * Get Gmail inbox messages
     */
    async getInbox(email, options = {}) {
        const gmail = this.gmailClients.get(email);
        if (!gmail) throw new Error(`Gmail not initialized for ${email}`);
        
        const response = await gmail.users.messages.list({
            userId: 'me',
            maxResults: options.maxResults || 20,
            q: options.query || '',
            labelIds: options.labelIds || ['INBOX']
        });
        
        const messages = [];
        for (const msg of response.data.messages || []) {
            const full = await gmail.users.messages.get({
                userId: 'me',
                id: msg.id,
                format: 'metadata',
                metadataHeaders: ['From', 'Subject', 'Date']
            });
            
            const headers = full.data.payload?.headers || [];
            messages.push({
                id: msg.id,
                threadId: msg.threadId,
                snippet: full.data.snippet,
                from: headers.find(h => h.name === 'From')?.value,
                subject: headers.find(h => h.name === 'Subject')?.value,
                date: headers.find(h => h.name === 'Date')?.value,
                labelIds: full.data.labelIds
            });
        }
        
        return { email, messages, count: messages.length };
    }

    /**
     * Get unread count for all accounts
     */
    async getAllUnreadCounts() {
        const counts = [];
        for (const account of this.accounts) {
            if (this.status.get(account.email)?.connected) {
                try {
                    const gmail = this.gmailClients.get(account.email);
                    const response = await gmail.users.messages.list({
                        userId: 'me',
                        q: 'is:unread',
                        maxResults: 100
                    });
                    counts.push({
                        email: account.email,
                        unread: response.data.resultSizeEstimate || 0
                    });
                } catch (error) {
                    counts.push({ email: account.email, error: error.message });
                }
            }
        }
        return counts;
    }

    /**
     * Send email
     */
    async sendEmail(email, to, subject, body, options = {}) {
        const gmail = this.gmailClients.get(email);
        if (!gmail) throw new Error(`Gmail not initialized for ${email}`);
        
        const message = [
            `From: ${email}`,
            `To: ${to}`,
            `Subject: ${subject}`,
            'Content-Type: text/html; charset=utf-8',
            '',
            body
        ].join('\r\n');
        
        const encodedMessage = Buffer.from(message)
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
        
        const response = await gmail.users.messages.send({
            userId: 'me',
            requestBody: { raw: encodedMessage }
        });
        
        return { success: true, messageId: response.data.id };
    }

    // ================================================================
    // CALENDAR API
    // ================================================================

    /**
     * Get upcoming events
     */
    async getEvents(email, options = {}) {
        const calendar = this.calendarClients.get(email);
        if (!calendar) throw new Error(`Calendar not initialized for ${email}`);
        
        const response = await calendar.events.list({
            calendarId: 'primary',
            timeMin: options.timeMin || new Date().toISOString(),
            maxResults: options.maxResults || 10,
            singleEvents: true,
            orderBy: 'startTime'
        });
        
        return {
            email,
            events: response.data.items || [],
            count: response.data.items?.length || 0
        };
    }

    /**
     * Create event
     */
    async createEvent(email, event) {
        const calendar = this.calendarClients.get(email);
        if (!calendar) throw new Error(`Calendar not initialized for ${email}`);
        
        const response = await calendar.events.insert({
            calendarId: 'primary',
            requestBody: event
        });
        
        return { success: true, event: response.data };
    }

    // ================================================================
    // DRIVE API
    // ================================================================

    /**
     * List files in Drive
     */
    async listFiles(email, options = {}) {
        const drive = this.driveClients.get(email);
        if (!drive) throw new Error(`Drive not initialized for ${email}`);
        
        const response = await drive.files.list({
            pageSize: options.pageSize || 20,
            fields: 'nextPageToken, files(id, name, mimeType, size, modifiedTime)',
            q: options.query || ''
        });
        
        return {
            email,
            files: response.data.files || [],
            nextPageToken: response.data.nextPageToken
        };
    }

    /**
     * Get Drive storage quota
     */
    async getStorageQuota(email) {
        const drive = this.driveClients.get(email);
        if (!drive) throw new Error(`Drive not initialized for ${email}`);
        
        const response = await drive.about.get({
            fields: 'storageQuota'
        });
        
        const quota = response.data.storageQuota;
        return {
            email,
            limit: parseInt(quota.limit),
            usage: parseInt(quota.usage),
            usageInDrive: parseInt(quota.usageInDrive),
            usagePercent: ((parseInt(quota.usage) / parseInt(quota.limit)) * 100).toFixed(2)
        };
    }

    // ================================================================
    // YOUTUBE API
    // ================================================================

    /**
     * Get user's playlists
     */
    async getPlaylists(email, options = {}) {
        const youtube = this.youtubeClients.get(email);
        if (!youtube) throw new Error(`YouTube not initialized for ${email}`);
        
        const response = await youtube.playlists.list({
            part: 'snippet,contentDetails',
            mine: true,
            maxResults: options.maxResults || 25
        });
        
        return {
            email,
            playlists: response.data.items || [],
            count: response.data.items?.length || 0
        };
    }

    /**
     * Get playlist items (videos)
     */
    async getPlaylistItems(email, playlistId, options = {}) {
        const youtube = this.youtubeClients.get(email);
        if (!youtube) throw new Error(`YouTube not initialized for ${email}`);
        
        const response = await youtube.playlistItems.list({
            part: 'snippet,contentDetails',
            playlistId: playlistId,
            maxResults: options.maxResults || 50
        });
        
        const videos = (response.data.items || []).map(item => ({
            id: item.contentDetails.videoId,
            title: item.snippet.title,
            description: item.snippet.description,
            thumbnail: item.snippet.thumbnails?.medium?.url,
            position: item.snippet.position,
            publishedAt: item.snippet.publishedAt
        }));
        
        return { email, playlistId, videos, count: videos.length };
    }

    /**
     * Search YouTube videos
     */
    async searchVideos(email, query, options = {}) {
        const youtube = this.youtubeClients.get(email);
        if (!youtube) throw new Error(`YouTube not initialized for ${email}`);
        
        const response = await youtube.search.list({
            part: 'snippet',
            q: query,
            type: 'video',
            maxResults: options.maxResults || 10,
            videoCategoryId: options.musicOnly ? '10' : undefined // 10 = Music category
        });
        
        const videos = (response.data.items || []).map(item => ({
            id: item.id.videoId,
            title: item.snippet.title,
            description: item.snippet.description,
            thumbnail: item.snippet.thumbnails?.medium?.url,
            channelTitle: item.snippet.channelTitle,
            publishedAt: item.snippet.publishedAt
        }));
        
        return { email, query, videos, count: videos.length };
    }

    /**
     * Get liked videos (Music recommendations)
     */
    async getLikedVideos(email, options = {}) {
        const youtube = this.youtubeClients.get(email);
        if (!youtube) throw new Error(`YouTube not initialized for ${email}`);
        
        const response = await youtube.videos.list({
            part: 'snippet,contentDetails',
            myRating: 'like',
            maxResults: options.maxResults || 50
        });
        
        const videos = (response.data.items || []).map(item => ({
            id: item.id,
            title: item.snippet.title,
            thumbnail: item.snippet.thumbnails?.medium?.url,
            duration: item.contentDetails.duration,
            channelTitle: item.snippet.channelTitle
        }));
        
        return { email, videos, count: videos.length };
    }

    // ================================================================
    // UTILITY METHODS
    // ================================================================

    /**
     * Disconnect an account
     */
    async disconnect(email) {
        const tokenPath = this.getTokenPath(email);
        if (fs.existsSync(tokenPath)) {
            fs.unlinkSync(tokenPath);
        }
        
        this.clients.delete(email);
        this.gmailClients.delete(email);
        this.calendarClients.delete(email);
        this.driveClients.delete(email);
        this.youtubeClients.delete(email);
        this.status.set(email, { connected: false, reason: 'Disconnected' });
        
        this.emit('disconnected', { email });
        return { success: true, email };
    }

    /**
     * Get primary account (first connected)
     */
    getPrimaryAccount() {
        for (const account of this.accounts) {
            if (this.status.get(account.email)?.connected) {
                return account.email;
            }
        }
        return null;
    }
}

module.exports = GoogleMultiAccountService;
