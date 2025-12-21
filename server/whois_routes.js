/**
 * IP2WHOIS API Routes
 * Domain WHOIS Lookup using ip2whois.com
 * 
 * API: https://api.ip2whois.com/v2
 * Features: Domain info, registrar, dates, nameservers
 */

const express = require('express');
const router = express.Router();

// IP2WHOIS API Key (same as IP2Location)
const API_KEY = process.env.IP2WHOIS_API_KEY || '7CB97DB64402CC3F7649A43BD6C2C9B9';
const BASE_URL = 'https://api.ip2whois.com/v2';

/**
 * GET /api/whois/lookup
 * Get WHOIS data for a domain
 * Query params: domain (required)
 * Example: /api/whois/lookup?domain=google.com
 */
router.get('/lookup', async (req, res) => {
    try {
        const { domain } = req.query;

        if (!domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'Domain parameter is required' 
            });
        }

        // Clean domain (remove http/https and paths)
        const cleanDomain = domain
            .replace(/^https?:\/\//, '')
            .replace(/\/.*$/, '')
            .toLowerCase();

        const response = await fetch(`${BASE_URL}?key=${API_KEY}&domain=${cleanDomain}`);
        const data = await response.json();

        if (data.error) {
            return res.status(400).json({
                success: false,
                error: data.error.error_message || 'WHOIS lookup failed'
            });
        }

        // Enhanced response with formatted data
        res.json({ 
            success: true, 
            data: {
                domain: data.domain,
                domain_id: data.domain_id,
                status: data.status,
                dates: {
                    created: data.create_date,
                    updated: data.update_date,
                    expires: data.expire_date,
                    age_days: data.domain_age
                },
                whois_server: data.whois_server,
                registrar: {
                    name: data.registrar?.name || 'N/A',
                    iana_id: data.registrar?.iana_id,
                    url: data.registrar?.url
                },
                contacts: {
                    registrant: data.registrant,
                    admin: data.admin,
                    tech: data.tech,
                    billing: data.billing
                },
                nameservers: data.nameservers || []
            }
        });
    } catch (error) {
        console.error('[WHOIS] Lookup Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/whois/raw
 * Get raw WHOIS API response
 */
router.get('/raw', async (req, res) => {
    try {
        const { domain } = req.query;

        if (!domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'Domain parameter is required' 
            });
        }

        const cleanDomain = domain
            .replace(/^https?:\/\//, '')
            .replace(/\/.*$/, '')
            .toLowerCase();

        const response = await fetch(`${BASE_URL}?key=${API_KEY}&domain=${cleanDomain}`);
        const data = await response.json();

        res.json({ success: true, raw: data });
    } catch (error) {
        console.error('[WHOIS] Raw Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * POST /api/whois/batch
 * Lookup multiple domains at once
 * Body: { domains: ["google.com", "github.com"] }
 */
router.post('/batch', async (req, res) => {
    try {
        const { domains } = req.body;

        if (!domains || !Array.isArray(domains) || domains.length === 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Array of domains required' 
            });
        }

        // Limit to 10 domains per batch
        const limitedDomains = domains.slice(0, 10);
        
        const results = await Promise.all(
            limitedDomains.map(async (domain) => {
                try {
                    const cleanDomain = domain
                        .replace(/^https?:\/\//, '')
                        .replace(/\/.*$/, '')
                        .toLowerCase();

                    const response = await fetch(`${BASE_URL}?key=${API_KEY}&domain=${cleanDomain}`);
                    const data = await response.json();
                    
                    if (data.error) {
                        return { domain, success: false, error: data.error.error_message };
                    }
                    
                    return {
                        domain: data.domain,
                        registrar: data.registrar?.name || 'N/A',
                        created: data.create_date,
                        expires: data.expire_date,
                        age_days: data.domain_age,
                        nameservers: data.nameservers?.length || 0,
                        success: true
                    };
                } catch (err) {
                    return { domain, success: false, error: err.message };
                }
            })
        );

        res.json({ 
            success: true, 
            count: results.length,
            results 
        });
    } catch (error) {
        console.error('[WHOIS] Batch Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/whois/check
 * Quick check if domain is available (based on WHOIS data)
 */
router.get('/check', async (req, res) => {
    try {
        const { domain } = req.query;

        if (!domain) {
            return res.status(400).json({ 
                success: false, 
                error: 'Domain parameter is required' 
            });
        }

        const cleanDomain = domain
            .replace(/^https?:\/\//, '')
            .replace(/\/.*$/, '')
            .toLowerCase();

        const response = await fetch(`${BASE_URL}?key=${API_KEY}&domain=${cleanDomain}`);
        const data = await response.json();

        // Check if domain exists
        const exists = !data.error && data.domain;
        const expiresDate = data.expire_date ? new Date(data.expire_date) : null;
        const isExpiringSoon = expiresDate && (expiresDate.getTime() - Date.now()) < 30 * 24 * 60 * 60 * 1000; // 30 days

        res.json({ 
            success: true,
            domain: cleanDomain,
            registered: exists,
            available: !exists,
            expires_soon: isExpiringSoon,
            expiration_date: data.expire_date || null,
            registrar: data.registrar?.name || null
        });
    } catch (error) {
        console.error('[WHOIS] Check Error:', error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

/**
 * GET /api/whois/status
 * Check API status
 */
router.get('/status', (req, res) => {
    res.json({
        success: true,
        service: 'ip2whois.com',
        configured: !!API_KEY,
        endpoints: [
            'GET /api/whois/lookup?domain=X - Full WHOIS lookup',
            'GET /api/whois/raw?domain=X - Raw API response',
            'GET /api/whois/check?domain=X - Quick availability check',
            'POST /api/whois/batch - Batch lookup (max 10 domains)'
        ],
        dataProvided: [
            'Domain ID & Status',
            'Creation/Update/Expiration dates',
            'Domain age (days)',
            'Registrar info',
            'Contact details (registrant, admin, tech, billing)',
            'Nameservers'
        ]
    });
});

module.exports = router;
