const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

class AstrometryService {
    constructor() {
        this.baseUrl = 'https://nova.astrometry.net/api';
        this.sessionKey = null;
    }

    async login(apiKey) {
        try {
            // Docs say: payload should be `request-json=JSON_STRING` sent as form-encoded
            const params = new URLSearchParams();
            params.append('request-json', JSON.stringify({ apikey: apiKey }));

            const response = await axios.post(`${this.baseUrl}/login`, params, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            if (response.data.status === 'success') {
                this.sessionKey = response.data.session;
                console.log('[ASTROMETRY] Logged in successfully. Session:', this.sessionKey);
                return this.sessionKey;
            } else {
                throw new Error('Login failed: ' + response.data.message);
            }
        } catch (error) {
            console.error('[ASTROMETRY] Login error:', error.message);
            throw error;
        }
    }

    async upload(filePath, apiKey) {
        if (!this.sessionKey) {
            await this.login(apiKey);
        }

        try {
            const fileStream = fs.createReadStream(filePath);
            const formData = new FormData();

            // Astrometry.net expects request-json as a string field
            formData.append('request-json', JSON.stringify({
                "publicly_visible": "y",
                "allow_commercial_use": "d",
                "allow_modifications": "d",
                "session": this.sessionKey
            }));
            formData.append('file', fileStream);

            const response = await axios.post(`${this.baseUrl}/upload`, formData, {
                headers: {
                    ...formData.getHeaders(),
                    // CRITICAL: Astrometry.net anti-bot protection
                    // 'Referer': 'https://nova.astrometry.net/api/login' // Often strictly checked? 
                    // Actually, the docs say for "downloading files programmatically", but good practice to include if needed.
                }
            });

            if (response.data.status === 'success') {
                return response.data.subid;
            } else {
                throw new Error('Upload failed: ' + response.data.message);
            }
        } catch (error) {
            console.error('[ASTROMETRY] Upload error:', error.message);
            throw error;
        }
    }

    async getSubmissionStatus(subId) {
        try {
            const response = await axios.get(`${this.baseUrl}/submissions/${subId}`);
            // keys: processing_finished, jobs (array), job_calibrations (array)
            return response.data;
        } catch (error) {
            console.error(`[ASTROMETRY] Submission status error (${subId}):`, error.message);
            throw error;
        }
    }

    async getJobStatus(jobId) {
        try {
            const response = await axios.get(`${this.baseUrl}/jobs/${jobId}`);
            return response.data; // status: 'success' or 'failure'
        } catch (error) {
            console.error(`[ASTROMETRY] Job status error (${jobId}):`, error.message);
            throw error;
        }
    }

    async getCalibration(jobId) {
        try {
            const response = await axios.get(`${this.baseUrl}/jobs/${jobId}/calibration`);
            return response.data; // ra, dec, etc.
        } catch (error) {
            console.error(`[ASTROMETRY] Calibration error (${jobId}):`, error.message);
            throw error;
        }
    }

    async getWCSFile(jobId) {
        try {
            // WWT needs the wcs file sometimes, but calibration endpoint usually gives simple ra/dec/scale
            // Let's stick to calibration first.
            const response = await axios.get(`${this.baseUrl}/jobs/${jobId}/calibration`);
            return response.data;
        } catch (error) {
            throw error;
        }
    }
}

module.exports = AstrometryService;
