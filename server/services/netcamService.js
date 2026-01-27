const { spawn, exec } = require('child_process');
const path = require('path');

// Netcam Studio Paths (Default Installation)
const NETCAM_EXE_PATH = "C:\\Program Files\\Netcam Studio - 64-bit\\NetcamStudioX.exe";
const NETCAM_API_URL = process.env.NETCAM_API_URL || 'http://127.0.0.1:8124';
const NETCAM_STREAM_URL = process.env.NETCAM_STREAM_URL || 'http://127.0.0.1:8100';

class NetcamService {
    constructor() {
        this.sessionToken = null;
        this.tokenExpiry = null;
        this.cameras = [];
        this.connected = false;
        this.processStarting = false;

        // Attempt to auto-start on initialization
        this.initialize();
    }

    async initialize() {
        console.log('[NETCAM] Initializing Netcam Service...');
        const isRunning = await this.testConnection();
        if (!isRunning.success) {
            console.log('[NETCAM] Server not detected. Attempting to start integrated process...');
            this.startServerProcess();
        } else {
            console.log('[NETCAM] Service detected and online.');
            this.connected = true;
        }
    }

    /**
     * Start Netcam Studio Process (Hidden/Integrated)
     */
    startServerProcess() {
        if (this.processStarting) return;
        this.processStarting = true;

        // Use PowerShell to start the process minimized/hidden to act as a background service
        // strictly integrated into the app flow
        const psCommand = `Start-Process -FilePath "${NETCAM_EXE_PATH}" -WindowStyle Minimized`;

        console.log('[NETCAM] Launching Netcam Studio process...');

        exec(`powershell -Command "${psCommand}"`, (error, stdout, stderr) => {
            this.processStarting = false;
            if (error) {
                console.error(`[NETCAM] Failed to start process: ${error.message}`);
                return;
            }
            console.log('[NETCAM] Process launch command executed successfully.');

            // Wait a bit for startup then connect
            setTimeout(() => this.login(), 5000);
        });
    }

    /**
     * Login to Netcam Studio and get session token
     */
    async login(username = 'admin', password = '1234') {
        try {
            const url = `${NETCAM_API_URL}/Json/Login?username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`;
            const response = await fetch(url);

            if (!response.ok) {
                // If login fails (e.g. 404/500), the server might be starting or down
                throw new Error(`Login failed: ${response.status}`);
            }

            const data = await response.json();

            if (data.SessionToken) {
                this.sessionToken = data.SessionToken;
                this.tokenExpiry = Date.now() + (9 * 60 * 1000); // 9 minutes (token expires after 10)
                this.connected = true;
                console.log('[NETCAM] ✅ Connected to integrated Netcam Studio');
                return { success: true, token: this.sessionToken };
            }

            throw new Error('No session token received');
        } catch (error) {
            console.error('[NETCAM] ❌ Connection failed (Server might be offline):', error.message);
            this.connected = false;

            // If connection refused, try to restart process if not already trying
            if (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED')) {
                // Optional: Retry logic could go here, but avoiding loops is safer
            }

            return { success: false, error: error.message };
        }
    }

    /**
     * Ensure we have a valid session token
     */
    async ensureAuthenticated() {
        if (!this.sessionToken || Date.now() > this.tokenExpiry) {
            return await this.login();
        }
        return { success: true, token: this.sessionToken };
    }

    /**
     * Get list of all cameras/sources
     */
    async getCameras() {
        try {
            await this.ensureAuthenticated();

            const url = `${NETCAM_API_URL}/Json/GetSources?token=${this.sessionToken}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to get cameras: ${response.status}`);
            }

            const data = await response.json();
            this.cameras = data.Sources || data || [];

            return {
                success: true,
                cameras: this.cameras.map((cam, index) => ({
                    id: cam.Id || cam.SourceId || index,
                    name: cam.Name || cam.SourceName || `Camera ${index + 1}`,
                    enabled: cam.Enabled !== false,
                    recording: cam.Recording || false,
                    motionDetection: cam.MotionDetection || false,
                    type: cam.SourceType || 'IP Camera',
                    status: cam.Status || 'unknown',
                    streamUrl: this.getStreamUrl(cam.Id || cam.SourceId || index),
                    snapshotUrl: this.getSnapshotUrl(cam.Id || cam.SourceId || index)
                }))
            };
        } catch (error) {
            console.error('[NETCAM] Error getting cameras:', error.message);
            return { success: false, error: error.message, cameras: [] };
        }
    }

    /**
     * Get MJPEG stream URL for a camera
     */
    getStreamUrl(cameraId) {
        return `${NETCAM_STREAM_URL}/Stream/mjpeg?sourceid=${cameraId}&token=${this.sessionToken}`;
    }

    /**
     * Get snapshot URL for a camera
     */
    getSnapshotUrl(cameraId) {
        return `${NETCAM_STREAM_URL}/GetImage?sourceid=${cameraId}&token=${this.sessionToken}`;
    }

    /**
     * Get camera status
     */
    async getCameraStatus(cameraId) {
        try {
            await this.ensureAuthenticated();

            const url = `${NETCAM_API_URL}/Json/GetSourceInfo?token=${this.sessionToken}&sourceid=${cameraId}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to get camera status: ${response.status}`);
            }

            const data = await response.json();
            return { success: true, status: data };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Start/Stop recording for a camera
     */
    async toggleRecording(cameraId, start = true) {
        try {
            await this.ensureAuthenticated();

            const action = start ? 'StartRecording' : 'StopRecording';
            const url = `${NETCAM_API_URL}/Json/${action}?token=${this.sessionToken}&sourceid=${cameraId}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to ${action}: ${response.status}`);
            }

            return { success: true, action, cameraId };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Enable/Disable motion detection
     */
    async toggleMotionDetection(cameraId, enable = true) {
        try {
            await this.ensureAuthenticated();

            const action = enable ? 'EnableMotionDetection' : 'DisableMotionDetection';
            const url = `${NETCAM_API_URL}/Json/${action}?token=${this.sessionToken}&sourceid=${cameraId}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to ${action}: ${response.status}`);
            }

            return { success: true, action, cameraId };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * PTZ Control (Pan-Tilt-Zoom)
     */
    async ptzControl(cameraId, command) {
        // Commands: up, down, left, right, zoomin, zoomout, stop
        try {
            await this.ensureAuthenticated();

            const url = `${NETCAM_API_URL}/Json/PTZ?token=${this.sessionToken}&sourceid=${cameraId}&command=${command}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`PTZ command failed: ${response.status}`);
            }

            return { success: true, command, cameraId };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Get recordings list
     */
    async getRecordings(cameraId = null, startDate = null, endDate = null) {
        try {
            await this.ensureAuthenticated();

            let url = `${NETCAM_API_URL}/Json/GetMediaFiles?token=${this.sessionToken}`;
            if (cameraId) url += `&sourceid=${cameraId}`;
            if (startDate) url += `&startdate=${startDate}`;
            if (endDate) url += `&enddate=${endDate}`;

            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to get recordings: ${response.status}`);
            }

            const data = await response.json();
            return { success: true, recordings: data.Files || data || [] };
        } catch (error) {
            return { success: false, error: error.message, recordings: [] };
        }
    }

    /**
     * Get system status
     */
    async getSystemStatus() {
        try {
            await this.ensureAuthenticated();

            const url = `${NETCAM_API_URL}/Json/GetServerInfo?token=${this.sessionToken}`;
            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`Failed to get system status: ${response.status}`);
            }

            const data = await response.json();
            return {
                success: true,
                connected: this.connected,
                server: {
                    version: data.Version || 'Unknown',
                    uptime: data.Uptime || 'Unknown',
                    cpu: data.CpuUsage || 0,
                    memory: data.MemoryUsage || 0,
                    disk: data.DiskUsage || 0,
                    activeSources: data.ActiveSources || 0,
                    recording: data.Recording || false
                }
            };
        } catch (error) {
            return {
                success: false,
                connected: false,
                error: error.message
            };
        }
    }

    /**
     * Test connection to Netcam Studio
     */
    async testConnection() {
        try {
            const response = await fetch(`${NETCAM_API_URL}/Json/GetServerVersion`, {
                timeout: 2000 // Short timeout for check
            });

            if (response.ok) {
                const data = await response.json();
                return {
                    success: true,
                    version: data.Version || 'Connected',
                    apiUrl: NETCAM_API_URL,
                    streamUrl: NETCAM_STREAM_URL
                };
            }

            throw new Error('Server detected but returning non-200');
        } catch (error) {
            return {
                success: false,
                error: error.message,
                apiUrl: NETCAM_API_URL,
                streamUrl: NETCAM_STREAM_URL
            };
        }
    }

    /**
     * Disconnect from Netcam Studio
     */
    async disconnect() {
        if (this.sessionToken) {
            try {
                await fetch(`${NETCAM_API_URL}/Json/Logout?token=${this.sessionToken}`);
            } catch (e) {
                // Ignore logout errors
            }
        }
        this.sessionToken = null;
        this.tokenExpiry = null;
        this.connected = false;
        console.log('[NETCAM] Disconnected');
    }
}

// Singleton instance
const netcamService = new NetcamService();

module.exports = netcamService;
