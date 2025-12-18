/**
 * EasyLife Camera Control Service
 * Th3 Thirty3 - IP Camera Integration
 * 
 * Supports:
 * - RTSP streaming
 * - ONVIF control (if supported)
 * - PTZ (Pan-Tilt-Zoom) commands
 * - Snapshot capture
 * - Motion detection settings
 */

const EventEmitter = require('events');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

class CameraService extends EventEmitter {
    constructor() {
        super();
        
        // Camera registry
        this.cameras = new Map();
        
        // Default credentials (common for EasyLife)
        this.defaultCredentials = {
            username: 'admin',
            password: 'admin'
        };
        
        // RTSP port (standard)
        this.defaultRtspPort = 554;
        
        // HTTP port for CGI commands
        this.defaultHttpPort = 80;
        
        // Snapshots directory
        this.snapshotsDir = path.join(__dirname, 'data', 'camera_snapshots');
        this.ensureSnapshotsDir();
        
        // Load saved cameras
        this.loadCameras();
        
        console.log('[CAMERA] EasyLife Camera Service initialized');
    }

    /**
     * Ensure snapshots directory exists
     */
    ensureSnapshotsDir() {
        if (!fs.existsSync(this.snapshotsDir)) {
            fs.mkdirSync(this.snapshotsDir, { recursive: true });
        }
    }

    /**
     * Load saved cameras from config
     */
    loadCameras() {
        const configPath = path.join(__dirname, 'data', 'cameras.json');
        try {
            if (fs.existsSync(configPath)) {
                const data = JSON.parse(fs.readFileSync(configPath, 'utf8'));
                data.forEach(cam => this.cameras.set(cam.id, cam));
                console.log(`[CAMERA] Loaded ${this.cameras.size} cameras from config`);
            }
        } catch (error) {
            console.error('[CAMERA] Error loading cameras:', error.message);
        }
    }

    /**
     * Save cameras to config
     */
    saveCameras() {
        const configPath = path.join(__dirname, 'data', 'cameras.json');
        try {
            const data = Array.from(this.cameras.values());
            fs.writeFileSync(configPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('[CAMERA] Error saving cameras:', error.message);
        }
    }

    /**
     * Add a new camera
     * @param {object} config - Camera configuration
     */
    addCamera(config) {
        const camera = {
            id: config.id || `cam_${Date.now()}`,
            name: config.name || 'EasyLife Camera',
            ip: config.ip,
            rtspPort: config.rtspPort || this.defaultRtspPort,
            httpPort: config.httpPort || this.defaultHttpPort,
            username: config.username || this.defaultCredentials.username,
            password: config.password || this.defaultCredentials.password,
            rtspPath: config.rtspPath || '/stream1',  // Common EasyLife path
            alternateRtspPaths: [
                '/stream1',
                '/h264_stream',
                '/live/ch00_0',
                '/cam/realmonitor?channel=1&subtype=0',
                '/Streaming/Channels/101',
                '/onvif1'
            ],
            model: config.model || 'EasyLife Generic',
            hasPTZ: config.hasPTZ || false,
            supportsONVIF: config.supportsONVIF || false,
            status: 'unknown',
            lastSeen: null,
            addedAt: new Date().toISOString()
        };

        this.cameras.set(camera.id, camera);
        this.saveCameras();
        
        console.log(`[CAMERA] Added camera: ${camera.name} (${camera.ip})`);
        return camera;
    }

    /**
     * Remove a camera
     */
    removeCamera(cameraId) {
        const deleted = this.cameras.delete(cameraId);
        if (deleted) {
            this.saveCameras();
            console.log(`[CAMERA] Removed camera: ${cameraId}`);
        }
        return deleted;
    }

    /**
     * Get all cameras
     */
    getAllCameras() {
        return Array.from(this.cameras.values());
    }

    /**
     * Get camera by ID
     */
    getCamera(cameraId) {
        return this.cameras.get(cameraId);
    }

    /**
     * Build RTSP URL for a camera
     */
    buildRtspUrl(camera, substream = false) {
        const path = substream ? '/stream2' : camera.rtspPath;
        return `rtsp://${camera.username}:${camera.password}@${camera.ip}:${camera.rtspPort}${path}`;
    }

    /**
     * Build HTTP URL for camera commands
     */
    buildHttpUrl(camera, path) {
        return `http://${camera.username}:${camera.password}@${camera.ip}:${camera.httpPort}${path}`;
    }

    /**
     * Test camera connection
     */
    async testConnection(cameraId) {
        const camera = this.cameras.get(cameraId);
        if (!camera) {
            return { success: false, error: 'Camera not found' };
        }

        const results = {
            rtsp: false,
            http: false,
            onvif: false,
            workingRtspPath: null
        };

        // Test HTTP connectivity
        try {
            const httpUrl = `http://${camera.ip}:${camera.httpPort}/`;
            const response = await fetch(httpUrl, { 
                signal: AbortSignal.timeout(5000),
                headers: {
                    'Authorization': 'Basic ' + Buffer.from(`${camera.username}:${camera.password}`).toString('base64')
                }
            });
            results.http = response.status < 500;
        } catch (e) {
            results.http = false;
        }

        // Test RTSP paths
        for (const rtspPath of camera.alternateRtspPaths) {
            const testUrl = `rtsp://${camera.username}:${camera.password}@${camera.ip}:${camera.rtspPort}${rtspPath}`;
            const rtspTest = await this.testRtspUrl(testUrl);
            if (rtspTest) {
                results.rtsp = true;
                results.workingRtspPath = rtspPath;
                
                // Update camera with working path
                camera.rtspPath = rtspPath;
                camera.status = 'online';
                camera.lastSeen = new Date().toISOString();
                this.saveCameras();
                break;
            }
        }

        if (!results.rtsp) {
            camera.status = 'offline';
            this.saveCameras();
        }

        return {
            success: results.rtsp || results.http,
            camera: camera.name,
            ip: camera.ip,
            results,
            rtspUrl: results.workingRtspPath ? this.buildRtspUrl(camera) : null
        };
    }

    /**
     * Test RTSP URL connectivity
     */
    async testRtspUrl(url) {
        return new Promise((resolve) => {
            // Use ffprobe to test RTSP stream
            const ffprobe = spawn('ffprobe', [
                '-v', 'quiet',
                '-rtsp_transport', 'tcp',
                '-timeout', '5000000',  // 5 seconds
                url
            ]);

            const timeout = setTimeout(() => {
                ffprobe.kill();
                resolve(false);
            }, 6000);

            ffprobe.on('close', (code) => {
                clearTimeout(timeout);
                resolve(code === 0);
            });

            ffprobe.on('error', () => {
                clearTimeout(timeout);
                resolve(false);
            });
        });
    }

    /**
     * Capture snapshot from camera
     */
    async captureSnapshot(cameraId) {
        const camera = this.cameras.get(cameraId);
        if (!camera) {
            return { success: false, error: 'Camera not found' };
        }

        const timestamp = Date.now();
        const filename = `${camera.id}_${timestamp}.jpg`;
        const filepath = path.join(this.snapshotsDir, filename);
        const rtspUrl = this.buildRtspUrl(camera);

        return new Promise((resolve) => {
            // Use ffmpeg to capture single frame
            const ffmpeg = spawn('ffmpeg', [
                '-y',
                '-rtsp_transport', 'tcp',
                '-i', rtspUrl,
                '-vframes', '1',
                '-q:v', '2',
                filepath
            ]);

            const timeout = setTimeout(() => {
                ffmpeg.kill();
                resolve({ success: false, error: 'Snapshot timeout' });
            }, 15000);

            ffmpeg.on('close', (code) => {
                clearTimeout(timeout);
                if (code === 0 && fs.existsSync(filepath)) {
                    resolve({
                        success: true,
                        camera: camera.name,
                        filename,
                        filepath,
                        timestamp: new Date().toISOString(),
                        url: `/api/cameras/snapshots/${filename}`
                    });
                } else {
                    resolve({ success: false, error: 'Snapshot capture failed' });
                }
            });

            ffmpeg.on('error', (err) => {
                clearTimeout(timeout);
                resolve({ success: false, error: err.message });
            });
        });
    }

    /**
     * PTZ Control - Move camera
     * @param {string} cameraId - Camera ID
     * @param {string} direction - up, down, left, right, home, zoomin, zoomout
     */
    async ptzControl(cameraId, direction, speed = 5) {
        const camera = this.cameras.get(cameraId);
        if (!camera) {
            return { success: false, error: 'Camera not found' };
        }

        if (!camera.hasPTZ) {
            return { success: false, error: 'Camera does not support PTZ' };
        }

        // Common CGI commands for PTZ (varies by manufacturer)
        const ptzCommands = {
            up: `/cgi-bin/ptz.cgi?action=start&channel=0&code=Up&arg1=0&arg2=${speed}&arg3=0`,
            down: `/cgi-bin/ptz.cgi?action=start&channel=0&code=Down&arg1=0&arg2=${speed}&arg3=0`,
            left: `/cgi-bin/ptz.cgi?action=start&channel=0&code=Left&arg1=0&arg2=${speed}&arg3=0`,
            right: `/cgi-bin/ptz.cgi?action=start&channel=0&code=Right&arg1=0&arg2=${speed}&arg3=0`,
            home: `/cgi-bin/ptz.cgi?action=start&channel=0&code=GotoPreset&arg1=0&arg2=1&arg3=0`,
            zoomin: `/cgi-bin/ptz.cgi?action=start&channel=0&code=ZoomTele&arg1=0&arg2=${speed}&arg3=0`,
            zoomout: `/cgi-bin/ptz.cgi?action=start&channel=0&code=ZoomWide&arg1=0&arg2=${speed}&arg3=0`,
            stop: `/cgi-bin/ptz.cgi?action=stop&channel=0&code=Up&arg1=0&arg2=0&arg3=0`
        };

        // Alternative ONVIF-style commands
        const onvifPtzCommands = {
            up: `/onvif/ptz?action=continuousmove&x=0&y=0.5&z=0`,
            down: `/onvif/ptz?action=continuousmove&x=0&y=-0.5&z=0`,
            left: `/onvif/ptz?action=continuousmove&x=-0.5&y=0&z=0`,
            right: `/onvif/ptz?action=continuousmove&x=0.5&y=0&z=0`,
            zoomin: `/onvif/ptz?action=continuousmove&x=0&y=0&z=0.5`,
            zoomout: `/onvif/ptz?action=continuousmove&x=0&y=0&z=-0.5`,
            stop: `/onvif/ptz?action=stop`
        };

        const command = camera.supportsONVIF ? onvifPtzCommands[direction] : ptzCommands[direction];
        if (!command) {
            return { success: false, error: 'Invalid PTZ direction' };
        }

        try {
            const url = this.buildHttpUrl(camera, command);
            const response = await fetch(url, {
                signal: AbortSignal.timeout(5000),
                headers: {
                    'Authorization': 'Basic ' + Buffer.from(`${camera.username}:${camera.password}`).toString('base64')
                }
            });

            return {
                success: response.ok,
                camera: camera.name,
                direction,
                speed
            };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    /**
     * Get RTSP stream info for embedding in frontend
     */
    getStreamInfo(cameraId) {
        const camera = this.cameras.get(cameraId);
        if (!camera) {
            return null;
        }

        return {
            id: camera.id,
            name: camera.name,
            rtspUrl: this.buildRtspUrl(camera),
            rtspUrlSubstream: this.buildRtspUrl(camera, true),
            httpUrl: `http://${camera.ip}:${camera.httpPort}`,
            hasPTZ: camera.hasPTZ,
            status: camera.status,
            // For web embedding, need WebRTC or HLS conversion
            webStreamUrl: `/api/cameras/stream/${camera.id}`,
            snapshotUrl: `/api/cameras/${camera.id}/snapshot`
        };
    }

    /**
     * Discover cameras on local network
     * Uses common IP ranges and ports
     */
    async discoverCameras(subnet = '192.168.1') {
        console.log(`[CAMERA] Scanning subnet ${subnet}.0/24 for cameras...`);
        const discovered = [];
        const commonPorts = [80, 554, 8080, 8554];

        // Scan IPs 1-254
        const scanPromises = [];
        
        for (let i = 1; i <= 254; i++) {
            const ip = `${subnet}.${i}`;
            scanPromises.push(this.probeCamera(ip, commonPorts));
        }

        const results = await Promise.all(scanPromises);
        
        results.forEach(result => {
            if (result.found) {
                discovered.push(result);
            }
        });

        console.log(`[CAMERA] Discovered ${discovered.length} potential cameras`);
        return discovered;
    }

    /**
     * Probe a single IP for camera
     */
    async probeCamera(ip, ports) {
        for (const port of ports) {
            try {
                const response = await fetch(`http://${ip}:${port}/`, {
                    signal: AbortSignal.timeout(1000)
                });
                
                const text = await response.text();
                
                // Check for common camera signatures
                if (text.toLowerCase().includes('camera') ||
                    text.toLowerCase().includes('dvr') ||
                    text.toLowerCase().includes('nvr') ||
                    text.toLowerCase().includes('hikvision') ||
                    text.toLowerCase().includes('dahua') ||
                    text.toLowerCase().includes('easylife') ||
                    text.toLowerCase().includes('onvif')) {
                    
                    return {
                        found: true,
                        ip,
                        port,
                        type: 'IP Camera',
                        signature: text.substring(0, 200)
                    };
                }
            } catch (e) {
                // Ignore connection errors
            }
        }
        
        return { found: false, ip };
    }

    /**
     * Get service status
     */
    getStatus() {
        const cameras = this.getAllCameras();
        return {
            totalCameras: cameras.length,
            online: cameras.filter(c => c.status === 'online').length,
            offline: cameras.filter(c => c.status === 'offline').length,
            unknown: cameras.filter(c => c.status === 'unknown').length,
            snapshotsDir: this.snapshotsDir,
            cameras: cameras.map(c => ({
                id: c.id,
                name: c.name,
                ip: c.ip,
                status: c.status,
                lastSeen: c.lastSeen,
                hasPTZ: c.hasPTZ
            }))
        };
    }
}

module.exports = CameraService;
