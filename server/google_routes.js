/**
 * Google Multi-Account API Routes
 * REST endpoints for Gmail, Calendar, Drive, and YouTube
 * 
 * @author Th3 Thirty3
 */
const express = require('express');
const router = express.Router();

module.exports = function(googleService) {
    
    // ================================================================
    // STATUS & AUTH
    // ================================================================

    /**
     * GET /api/google/status
     * Get overall service status
     */
    router.get('/status', (req, res) => {
        try {
            const status = googleService.getStatus();
            res.json(status);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/auth/:email
     * Get OAuth2 authorization URL for an account
     */
    router.get('/auth/:email', (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const authUrl = googleService.getAuthUrl(email);
            res.json({ success: true, email, authUrl });
        } catch (error) {
            res.status(400).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/callback
     * Handle OAuth2 callback
     */
    router.get('/callback', async (req, res) => {
        try {
            const { code, state } = req.query;
            const email = state; // Email passed as state
            
            if (!email || !code) {
                return res.status(400).json({ error: 'Missing email or code' });
            }
            
            await googleService.handleCallback(email, code);
            res.redirect(`/settings?google_connected=${encodeURIComponent(email)}`);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /api/google/disconnect/:email
     * Disconnect an account
     */
    router.post('/disconnect/:email', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const result = await googleService.disconnect(email);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ================================================================
    // GMAIL ENDPOINTS
    // ================================================================

    /**
     * GET /api/google/gmail/:email/inbox
     * Get inbox messages
     */
    router.get('/gmail/:email/inbox', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const options = {
                maxResults: parseInt(req.query.limit) || 20,
                query: req.query.q || ''
            };
            const result = await googleService.getInbox(email, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/gmail/unread
     * Get unread count for all accounts
     */
    router.get('/gmail/unread', async (req, res) => {
        try {
            const counts = await googleService.getAllUnreadCounts();
            res.json({ success: true, accounts: counts });
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /api/google/gmail/:email/send
     * Send email
     */
    router.post('/gmail/:email/send', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const { to, subject, body } = req.body;
            
            if (!to || !subject || !body) {
                return res.status(400).json({ error: 'Missing to, subject, or body' });
            }
            
            const result = await googleService.sendEmail(email, to, subject, body);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ================================================================
    // CALENDAR ENDPOINTS
    // ================================================================

    /**
     * GET /api/google/calendar/:email/events
     * Get upcoming events
     */
    router.get('/calendar/:email/events', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const options = {
                maxResults: parseInt(req.query.limit) || 10
            };
            const result = await googleService.getEvents(email, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * POST /api/google/calendar/:email/events
     * Create event
     */
    router.post('/calendar/:email/events', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const event = req.body;
            const result = await googleService.createEvent(email, event);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ================================================================
    // DRIVE ENDPOINTS
    // ================================================================

    /**
     * GET /api/google/drive/:email/files
     * List files
     */
    router.get('/drive/:email/files', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const options = {
                pageSize: parseInt(req.query.limit) || 20,
                query: req.query.q || ''
            };
            const result = await googleService.listFiles(email, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/drive/:email/quota
     * Get storage quota
     */
    router.get('/drive/:email/quota', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const result = await googleService.getStorageQuota(email);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ================================================================
    // YOUTUBE ENDPOINTS
    // ================================================================

    /**
     * GET /api/google/youtube/:email/playlists
     * Get user's playlists
     */
    router.get('/youtube/:email/playlists', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const options = {
                maxResults: parseInt(req.query.limit) || 25
            };
            const result = await googleService.getPlaylists(email, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/youtube/:email/playlist/:playlistId
     * Get playlist videos
     */
    router.get('/youtube/:email/playlist/:playlistId', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const playlistId = req.params.playlistId;
            const options = {
                maxResults: parseInt(req.query.limit) || 50
            };
            const result = await googleService.getPlaylistItems(email, playlistId, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/youtube/:email/search
     * Search YouTube videos
     */
    router.get('/youtube/:email/search', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const query = req.query.q;
            
            if (!query) {
                return res.status(400).json({ error: 'Missing query parameter q' });
            }
            
            const options = {
                maxResults: parseInt(req.query.limit) || 10,
                musicOnly: req.query.music === 'true'
            };
            const result = await googleService.searchVideos(email, query, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    /**
     * GET /api/google/youtube/:email/liked
     * Get liked videos
     */
    router.get('/youtube/:email/liked', async (req, res) => {
        try {
            const email = decodeURIComponent(req.params.email);
            const options = {
                maxResults: parseInt(req.query.limit) || 50
            };
            const result = await googleService.getLikedVideos(email, options);
            res.json(result);
        } catch (error) {
            res.status(500).json({ error: error.message });
        }
    });

    // ================================================================
    // HELP / DOCUMENTATION
    // ================================================================

    /**
     * GET /api/google/help
     * API documentation
     */
    router.get('/help', (req, res) => {
        res.json({
            service: 'Google Multi-Account Service',
            version: '2.0.0',
            accounts: [
                'mikegauthierguillet@gmail.com',
                'th3thirty3@gmail.com',
                'mgauthierguillet@gmail.com'
            ],
            endpoints: {
                status: {
                    'GET /status': 'Get overall service status',
                    'GET /auth/:email': 'Get OAuth2 URL for account',
                    'POST /disconnect/:email': 'Disconnect account'
                },
                gmail: {
                    'GET /gmail/:email/inbox': 'Get inbox messages',
                    'GET /gmail/unread': 'Get unread counts all accounts',
                    'POST /gmail/:email/send': 'Send email { to, subject, body }'
                },
                calendar: {
                    'GET /calendar/:email/events': 'Get upcoming events',
                    'POST /calendar/:email/events': 'Create event'
                },
                drive: {
                    'GET /drive/:email/files': 'List files',
                    'GET /drive/:email/quota': 'Get storage quota'
                },
                youtube: {
                    'GET /youtube/:email/playlists': 'Get playlists',
                    'GET /youtube/:email/playlist/:id': 'Get playlist videos',
                    'GET /youtube/:email/search?q=query': 'Search videos',
                    'GET /youtube/:email/liked': 'Get liked videos'
                }
            }
        });
    });

    return router;
};
