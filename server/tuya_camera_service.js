/**
 * Tuya Camera Service
 * Local control of EasyLife/Tuya cameras
 * 
 * Requirements:
 * - Device ID (from Tuya IoT Developer Platform or app)
 * - Local Key (from Tuya IoT Developer Platform)
 * - Device IP (discovered via network scan)
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const dgram = require('dgram');
const net = require('net');
const path = require('path');
const fs = require('fs');

class TuyaCameraService extends EventEmitter {
    constructor() {
        super();
        
        // Device registry
        this.devices = new Map();
        
        // Tuya protocol constants
        this.TUYA_PREFIX = Buffer.from([0x00, 0x00, 0x55, 0xAA]);
        this.TUYA_SUFFIX = Buffer.from([0x00, 0x00, 0xAA, 0x55]);
        
        // Command types
        this.COMMANDS = {
            DP_QUERY: 0x0A,      // Query device status
            CONTROL: 0x07,       // Send control command
            HEART_BEAT: 0x09,    // Heartbeat
            DP_QUERY_NEW: 0x10,  // New query command
            SESS_KEY_NEG_START: 0x03,  // Session key negotiation
            SESS_KEY_NEG_RESP: 0x04,
            SESS_KEY_NEG_FINISH: 0x05
        };
        
        // Camera Data Points (DPs) - Common for Tuya cameras
        this.CAMERA_DPS = {
            POWER: '1',           // Power on/off
            MOTION_DETECT: '103', // Motion detection
            RECORD_SWITCH: '104', // Recording on/off
            PTZ_CONTROL: '119',   // PTZ commands (up/down/left/right)
            PTZ_STOP: '116',      // Stop PTZ movement
            ZOOM: '117',          // Zoom control
            CRUISE_SWITCH: '110', // Auto patrol
            NIGHT_VISION: '108',  // Night vision mode (auto/on/off)
            FLIP: '106',          // Image flip
            WATERMARK: '105',     // Watermark toggle
            TIME_ZONE: '112',     // Timezone setting
            // PTZ direction values
            PTZ_UP: '0',
            PTZ_DOWN: '2',
            PTZ_LEFT: '6',
            PTZ_RIGHT: '4',
            PTZ_STOP_VAL: '1'
        };
        
        // Config path
        this.configPath = path.join(__dirname, 'data', 'tuya_devices.json');
        
        // Load saved devices
        this.loadDevices();
        
        console.log('[TUYA] Camera Service initialized');
    }

    /**
     * Load devices from config
     */
    loadDevices() {
        try {
            if (fs.existsSync(this.configPath)) {
                const data = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
                data.forEach(dev => this.devices.set(dev.id, dev));
                console.log(`[TUYA] Loaded ${this.devices.size} devices`);
            }
        } catch (error) {
            console.error('[TUYA] Error loading devices:', error.message);
        }
    }

    /**
     * Save devices to config
     */
    saveDevices() {
        try {
            const data = Array.from(this.devices.values());
            fs.writeFileSync(this.configPath, JSON.stringify(data, null, 2));
        } catch (error) {
            console.error('[TUYA] Error saving devices:', error.message);
        }
    }

    /**
     * Add a Tuya device
     * @param {object} config - Device configuration
     */
    addDevice(config) {
        const device = {
            id: config.deviceId || config.id,
            name: config.name || 'EasyLife Camera',
            ip: config.ip,
            localKey: config.localKey,
            version: config.version || '3.3', // Protocol version (3.1, 3.3, 3.4)
            port: config.port || 6668,
            type: 'camera',
            hasPTZ: config.hasPTZ !== false,
            status: 'unknown',
            lastSeen: null,
            addedAt: new Date().toISOString(),
            dps: {}  // Current device data points
        };

        this.devices.set(device.id, device);
        this.saveDevices();
        
        console.log(`[TUYA] Added device: ${device.name} (${device.ip})`);
        return device;
    }

    /**
     * Remove a device
     */
    removeDevice(deviceId) {
        const deleted = this.devices.delete(deviceId);
        if (deleted) {
            this.saveDevices();
        }
        return deleted;
    }

    /**
     * Get all devices
     */
    getAllDevices() {
        return Array.from(this.devices.values());
    }

    /**
     * Get device by ID
     */
    getDevice(deviceId) {
        return this.devices.get(deviceId);
    }

    /**
     * Encrypt data for Tuya protocol
     */
    encrypt(data, key, version = '3.3') {
        const keyBuffer = Buffer.from(key, 'utf8');
        const cipher = crypto.createCipheriv('aes-128-ecb', keyBuffer.slice(0, 16), null);
        let encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');
        return encrypted;
    }

    /**
     * Decrypt data from Tuya protocol
     */
    decrypt(data, key, version = '3.3') {
        try {
            const keyBuffer = Buffer.from(key, 'utf8');
            const decipher = crypto.createDecipheriv('aes-128-ecb', keyBuffer.slice(0, 16), null);
            let decrypted = decipher.update(data, 'base64', 'utf8');
            decrypted += decipher.final('utf8');
            return JSON.parse(decrypted);
        } catch (e) {
            return null;
        }
    }

    /**
     * Build Tuya protocol message
     */
    buildMessage(command, data, deviceId, key, version = '3.3') {
        const payload = JSON.stringify(data);
        const encrypted = this.encrypt(payload, key, version);
        
        // Calculate CRC
        const sequenceN = Math.floor(Math.random() * 0xFFFFFFFF);
        
        // Build header
        const header = Buffer.alloc(16);
        this.TUYA_PREFIX.copy(header);
        header.writeUInt32BE(sequenceN, 4);
        header.writeUInt32BE(command, 8);
        header.writeUInt32BE(Buffer.from(encrypted, 'base64').length + 8, 12);
        
        // Combine all parts
        const message = Buffer.concat([
            header,
            Buffer.from(encrypted, 'base64'),
            Buffer.alloc(4), // CRC placeholder
            this.TUYA_SUFFIX
        ]);
        
        return message;
    }

    /**
     * Send command to device
     */
    async sendCommand(deviceId, command, data) {
        const device = this.devices.get(deviceId);
        if (!device) {
            return { success: false, error: 'Device not found' };
        }

        if (!device.localKey) {
            return { success: false, error: 'Local key not configured. Get it from Tuya IoT Developer Platform' };
        }

        return new Promise((resolve) => {
            const client = new net.Socket();
            const timeout = setTimeout(() => {
                client.destroy();
                resolve({ success: false, error: 'Connection timeout' });
            }, 10000);

            client.connect(device.port, device.ip, () => {
                const message = this.buildMessage(command, data, device.id, device.localKey, device.version);
                client.write(message);
            });

            client.on('data', (response) => {
                clearTimeout(timeout);
                client.destroy();
                
                // Update device status
                device.status = 'online';
                device.lastSeen = new Date().toISOString();
                this.saveDevices();
                
                resolve({ 
                    success: true, 
                    device: device.name,
                    response: response.toString('hex')
                });
            });

            client.on('error', (err) => {
                clearTimeout(timeout);
                device.status = 'offline';
                this.saveDevices();
                resolve({ success: false, error: err.message });
            });
        });
    }

    /**
     * Query device status
     */
    async queryStatus(deviceId) {
        return this.sendCommand(deviceId, this.COMMANDS.DP_QUERY, {
            gwId: deviceId,
            devId: deviceId,
            uid: deviceId,
            t: Math.floor(Date.now() / 1000).toString()
        });
    }

    /**
     * Set device data point
     */
    async setDps(deviceId, dps) {
        const device = this.devices.get(deviceId);
        if (!device) {
            return { success: false, error: 'Device not found' };
        }

        return this.sendCommand(deviceId, this.COMMANDS.CONTROL, {
            gwId: device.id,
            devId: device.id,
            uid: device.id,
            t: Math.floor(Date.now() / 1000).toString(),
            dps: dps
        });
    }

    /**
     * PTZ Control
     */
    async ptzControl(deviceId, direction, duration = 500) {
        const directions = {
            up: this.CAMERA_DPS.PTZ_UP,
            down: this.CAMERA_DPS.PTZ_DOWN,
            left: this.CAMERA_DPS.PTZ_LEFT,
            right: this.CAMERA_DPS.PTZ_RIGHT,
            stop: this.CAMERA_DPS.PTZ_STOP_VAL
        };

        const dirValue = directions[direction.toLowerCase()];
        if (!dirValue) {
            return { success: false, error: 'Invalid direction. Use: up, down, left, right, stop' };
        }

        // Send PTZ command
        const result = await this.setDps(deviceId, {
            [this.CAMERA_DPS.PTZ_CONTROL]: dirValue
        });

        // Auto-stop after duration (except if stopping)
        if (result.success && direction !== 'stop') {
            setTimeout(async () => {
                await this.setDps(deviceId, {
                    [this.CAMERA_DPS.PTZ_CONTROL]: this.CAMERA_DPS.PTZ_STOP_VAL
                });
            }, duration);
        }

        return result;
    }

    /**
     * Toggle night vision
     */
    async setNightVision(deviceId, mode = 'auto') {
        const modes = { auto: '0', on: '1', off: '2' };
        return this.setDps(deviceId, {
            [this.CAMERA_DPS.NIGHT_VISION]: modes[mode] || '0'
        });
    }

    /**
     * Toggle motion detection
     */
    async setMotionDetection(deviceId, enabled) {
        return this.setDps(deviceId, {
            [this.CAMERA_DPS.MOTION_DETECT]: enabled
        });
    }

    /**
     * Toggle recording
     */
    async setRecording(deviceId, enabled) {
        return this.setDps(deviceId, {
            [this.CAMERA_DPS.RECORD_SWITCH]: enabled
        });
    }

    /**
     * Toggle power
     */
    async setPower(deviceId, on) {
        return this.setDps(deviceId, {
            [this.CAMERA_DPS.POWER]: on
        });
    }

    /**
     * Discover Tuya devices on network
     * Uses UDP broadcast to find devices
     */
    async discoverDevices(timeout = 10000) {
        return new Promise((resolve) => {
            const discovered = [];
            const socket = dgram.createSocket('udp4');
            
            const timeoutId = setTimeout(() => {
                socket.close();
                console.log(`[TUYA] Discovery complete. Found ${discovered.length} devices`);
                resolve(discovered);
            }, timeout);

            socket.on('message', (msg, rinfo) => {
                try {
                    // Try to parse Tuya discovery response
                    const data = this.parseDiscoveryResponse(msg);
                    if (data) {
                        discovered.push({
                            ip: rinfo.address,
                            ...data
                        });
                    }
                } catch (e) {
                    // Not a Tuya device
                }
            });

            socket.on('listening', () => {
                socket.setBroadcast(true);
                console.log('[TUYA] Discovery started...');
            });

            socket.bind(6667);  // Tuya discovery port
        });
    }

    /**
     * Parse discovery response
     */
    parseDiscoveryResponse(data) {
        // Tuya discovery packets start with specific bytes
        if (data.length < 20) return null;
        
        try {
            // Try to decrypt with default key
            const key = 'yGAdlopoPVldABfn';  // Default Tuya discovery key
            const encrypted = data.slice(20, data.length - 8);
            const decrypted = this.decrypt(encrypted.toString('base64'), key);
            return decrypted;
        } catch (e) {
            return null;
        }
    }

    /**
     * Test device connectivity
     */
    async testConnection(deviceId) {
        const device = this.devices.get(deviceId);
        if (!device) {
            return { success: false, error: 'Device not found' };
        }

        // Test TCP connection to device port
        return new Promise((resolve) => {
            const client = new net.Socket();
            const timeout = setTimeout(() => {
                client.destroy();
                device.status = 'offline';
                this.saveDevices();
                resolve({ 
                    success: false, 
                    device: device.name,
                    error: 'Connection timeout',
                    note: 'Make sure the device is on the same network and port 6668 is accessible'
                });
            }, 5000);

            client.connect(device.port, device.ip, () => {
                clearTimeout(timeout);
                client.destroy();
                device.status = 'online';
                device.lastSeen = new Date().toISOString();
                this.saveDevices();
                resolve({ 
                    success: true, 
                    device: device.name,
                    ip: device.ip,
                    port: device.port,
                    hasLocalKey: !!device.localKey,
                    message: device.localKey ? 
                        'Device reachable and configured' : 
                        'Device reachable but needs Local Key'
                });
            });

            client.on('error', (err) => {
                clearTimeout(timeout);
                device.status = 'offline';
                this.saveDevices();
                resolve({ 
                    success: false, 
                    device: device.name,
                    error: err.message 
                });
            });
        });
    }

    /**
     * Get service status
     */
    getStatus() {
        const devices = this.getAllDevices();
        return {
            service: 'Tuya Camera Service',
            totalDevices: devices.length,
            online: devices.filter(d => d.status === 'online').length,
            offline: devices.filter(d => d.status === 'offline').length,
            configured: devices.filter(d => d.localKey).length,
            devices: devices.map(d => ({
                id: d.id,
                name: d.name,
                ip: d.ip,
                status: d.status,
                hasLocalKey: !!d.localKey,
                hasPTZ: d.hasPTZ,
                lastSeen: d.lastSeen
            }))
        };
    }

    /**
     * Get instructions for obtaining Local Key
     */
    getLocalKeyInstructions() {
        return {
            title: 'Comment obtenir le Local Key de votre caméra EasyLife/Tuya',
            steps: [
                {
                    step: 1,
                    title: 'Créer un compte Tuya IoT Developer',
                    description: 'Allez sur https://iot.tuya.com et créez un compte gratuit'
                },
                {
                    step: 2,
                    title: 'Créer un Cloud Project',
                    description: 'Dans la console, créez un nouveau "Cloud Project" avec les APIs: Smart Home Family Management, Smart Home Device Manager'
                },
                {
                    step: 3,
                    title: 'Lier votre app Ease Life',
                    description: 'Dans le projet, allez dans "Link Tuya App Account" et scannez le QR code avec l\'app Ease Life (Profil > Settings > Scan QR)'
                },
                {
                    step: 4,
                    title: 'Récupérer le Local Key',
                    description: 'Allez dans "Devices" > Sélectionnez votre caméra > Copiez le "Local Key" (ou Device Secret)'
                },
                {
                    step: 5,
                    title: 'Configurer dans Th3 Thirty3',
                    description: 'Utilisez le Local Key avec l\'API: POST /api/tuya/devices avec deviceId, localKey, ip'
                }
            ],
            alternativeMethod: {
                title: 'Méthode alternative avec TinyTuya (Python)',
                steps: [
                    'pip install tinytuya',
                    'python -m tinytuya wizard',
                    'Suivez les instructions pour obtenir les clés de tous vos appareils'
                ]
            }
        };
    }
}

module.exports = TuyaCameraService;
