/**
 * Tuya Cloud API Service
 * For EasyLife cameras that don't support local control
 * Uses Tuya Cloud API for remote control
 */

const crypto = require('crypto');
const https = require('https');

class TuyaCloudService {
    constructor(config = {}) {
        // Tuya Cloud API endpoints by region
        this.endpoints = {
            us: 'https://openapi.tuyaus.com',
            eu: 'https://openapi.tuyaeu.com',
            cn: 'https://openapi.tuyacn.com',
            in: 'https://openapi.tuyain.com'
        };
        
        // Config from environment or direct
        this.clientId = config.clientId || process.env.TUYA_CLIENT_ID || '';
        this.clientSecret = config.clientSecret || process.env.TUYA_CLIENT_SECRET || '';
        this.region = config.region || process.env.TUYA_REGION || 'us';
        this.baseUrl = this.endpoints[this.region];
        
        // Token cache
        this.accessToken = null;
        this.tokenExpiry = 0;
        
        console.log('[TUYA-CLOUD] Service initialized');
    }

    /**
     * Generate signature for Tuya Cloud API
     */
    generateSign(method, path, timestamp, accessToken = '', body = '') {
        const contentHash = crypto.createHash('sha256').update(body).digest('hex');
        const stringToSign = [method, contentHash, '', path].join('\n');
        const signStr = this.clientId + (accessToken || '') + timestamp + stringToSign;
        
        const sign = crypto.createHmac('sha256', this.clientSecret)
            .update(signStr)
            .digest('hex')
            .toUpperCase();
        
        return sign;
    }

    /**
     * Make authenticated request to Tuya Cloud
     */
    async request(method, path, body = null) {
        // Ensure we have a valid token
        if (!this.accessToken || Date.now() > this.tokenExpiry) {
            await this.getAccessToken();
        }

        const timestamp = Date.now().toString();
        const bodyStr = body ? JSON.stringify(body) : '';
        const sign = this.generateSign(method, path, timestamp, this.accessToken, bodyStr);

        const options = {
            hostname: new URL(this.baseUrl).hostname,
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'client_id': this.clientId,
                'sign': sign,
                'sign_method': 'HMAC-SHA256',
                't': timestamp,
                'access_token': this.accessToken
            }
        };

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(e);
                    }
                });
            });
            
            req.on('error', reject);
            
            if (bodyStr) {
                req.write(bodyStr);
            }
            req.end();
        });
    }

    /**
     * Get access token from Tuya Cloud
     */
    async getAccessToken() {
        const timestamp = Date.now().toString();
        const path = '/v1.0/token?grant_type=1';
        const sign = this.generateSign('GET', path, timestamp);

        const options = {
            hostname: new URL(this.baseUrl).hostname,
            path: path,
            method: 'GET',
            headers: {
                'client_id': this.clientId,
                'sign': sign,
                'sign_method': 'HMAC-SHA256',
                't': timestamp
            }
        };

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const result = JSON.parse(data);
                        if (result.success && result.result) {
                            this.accessToken = result.result.access_token;
                            this.tokenExpiry = Date.now() + (result.result.expire_time * 1000) - 60000;
                            resolve(result.result);
                        } else {
                            reject(new Error(result.msg || 'Failed to get token'));
                        }
                    } catch (e) {
                        reject(e);
                    }
                });
            });
            
            req.on('error', reject);
            req.end();
        });
    }

    /**
     * Get list of devices
     */
    async getDevices() {
        return this.request('GET', '/v1.0/users/me/devices');
    }

    /**
     * Get device details
     */
    async getDevice(deviceId) {
        return this.request('GET', `/v1.0/devices/${deviceId}`);
    }

    /**
     * Get device status (data points)
     */
    async getDeviceStatus(deviceId) {
        return this.request('GET', `/v1.0/devices/${deviceId}/status`);
    }

    /**
     * Send commands to device
     */
    async sendCommands(deviceId, commands) {
        return this.request('POST', `/v1.0/devices/${deviceId}/commands`, {
            commands: commands
        });
    }

    /**
     * PTZ Control for cameras
     */
    async ptzControl(deviceId, direction) {
        const ptzCodes = {
            up: '0',
            down: '2',
            left: '6',
            right: '4',
            stop: '1'
        };

        return this.sendCommands(deviceId, [{
            code: 'ptz_control',
            value: ptzCodes[direction] || '1'
        }]);
    }

    /**
     * Get RTSP stream URL from Tuya Cloud
     */
    async getStreamUrl(deviceId) {
        return this.request('POST', `/v1.0/devices/${deviceId}/stream/actions/allocate`, {
            type: 'rtsp'
        });
    }

    /**
     * Get HLS stream URL
     */
    async getHlsStreamUrl(deviceId) {
        return this.request('POST', `/v1.0/devices/${deviceId}/stream/actions/allocate`, {
            type: 'hls'
        });
    }

    /**
     * Configure the service with credentials
     */
    configure(clientId, clientSecret, region = 'us') {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.region = region;
        this.baseUrl = this.endpoints[region];
        this.accessToken = null;
        this.tokenExpiry = 0;
        
        return { success: true, message: 'Tuya Cloud configured' };
    }

    /**
     * Get service status
     */
    async getStatus() {
        const configured = !!(this.clientId && this.clientSecret);
        
        if (!configured) {
            return {
                configured: false,
                message: 'Tuya Cloud API not configured',
                instructions: 'Set TUYA_CLIENT_ID and TUYA_CLIENT_SECRET in .env, or call /configure'
            };
        }

        try {
            const token = await this.getAccessToken();
            const devices = await this.getDevices();
            
            return {
                configured: true,
                connected: true,
                region: this.region,
                tokenExpiry: new Date(this.tokenExpiry).toISOString(),
                deviceCount: devices.result?.length || 0
            };
        } catch (error) {
            return {
                configured: true,
                connected: false,
                error: error.message
            };
        }
    }
}

module.exports = TuyaCloudService;
