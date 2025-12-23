/**
 * Camera Discovery Service
 * Passive camera discovery for personal network (EasyLife/Tuya)
 * 
 * Features:
 * - Network scanning via PowerShell/nmap
 * - Port scanning for camera ports
 * - ONVIF detection (via Python)
 * - Manufacturer fingerprinting
 * - WSL integration for Linux scripts
 * 
 * ⚠️ For authorized use on YOUR OWN network only!
 */

const EventEmitter = require('events');
const { spawn, exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const net = require('net');
const http = require('http');

class CameraDiscoveryService extends EventEmitter {
    constructor() {
        super();
        
        // Configuration
        this.scriptsDir = path.join(__dirname, '..', 'scripts');
        this.dataDir = path.join(__dirname, 'data', 'camera_scans');
        
        // Camera ports to scan
        this.cameraPorts = [80, 554, 8080, 8081, 6668, 9000, 37777, 34567];
        
        // Scan state
        this.isScanning = false;
        this.lastScan = null;
        this.discoveredCameras = [];
        
        // Manufacturer fingerprints (HTTP Server headers)
        this.fingerprints = {
            'hikvision': { manufacturer: 'Hikvision', confidence: 95 },
            'dahua': { manufacturer: 'Dahua', confidence: 95 },
            'foscam': { manufacturer: 'Foscam', confidence: 90 },
            'axis': { manufacturer: 'Axis', confidence: 95 },
            'goahead': { manufacturer: 'Generic Chinese', confidence: 70 },
            'boa': { manufacturer: 'EasyLife/Tuya', confidence: 85 },
            'thttpd': { manufacturer: 'Generic', confidence: 60 },
            'mini_httpd': { manufacturer: 'Generic', confidence: 60 },
            'easylife': { manufacturer: 'EasyLife', confidence: 95 },
            'tuya': { manufacturer: 'Tuya', confidence: 90 }
        };
        
        // Ensure data directory exists
        if (!fs.existsSync(this.dataDir)) {
            fs.mkdirSync(this.dataDir, { recursive: true });
        }
        
        // Load last scan results
        this._loadLastScan();
        
        console.log('[CAMERA-DISCOVERY] Service initialized');
    }

    /**
     * Load last scan results from file
     */
    _loadLastScan() {
        try {
            const latestFile = path.join(this.dataDir, 'latest_scan.json');
            if (fs.existsSync(latestFile)) {
                const data = JSON.parse(fs.readFileSync(latestFile, 'utf8'));
                this.lastScan = data;
                this.discoveredCameras = data.cameras || [];
                console.log(`[CAMERA-DISCOVERY] Loaded ${this.discoveredCameras.length} cameras from last scan`);
            }
        } catch (error) {
            console.error('[CAMERA-DISCOVERY] Error loading last scan:', error.message);
        }
    }

    /**
     * Save scan results to file
     */
    _saveScanResults(results) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `scan_${timestamp}.json`;
            
            // Save timestamped file
            fs.writeFileSync(
                path.join(this.dataDir, filename),
                JSON.stringify(results, null, 2)
            );
            
            // Save as latest
            fs.writeFileSync(
                path.join(this.dataDir, 'latest_scan.json'),
                JSON.stringify(results, null, 2)
            );
            
            this.lastScan = results;
            this.discoveredCameras = results.cameras || [];
            
            return filename;
        } catch (error) {
            console.error('[CAMERA-DISCOVERY] Error saving results:', error.message);
            return null;
        }
    }

    /**
     * Get default network range based on system IP
     */
    async getDefaultNetworkRange() {
        return new Promise((resolve) => {
            exec('ipconfig', (error, stdout) => {
                if (error) {
                    resolve('192.168.1.0/24'); // Default fallback
                    return;
                }
                
                // Parse IPv4 address from ipconfig
                const lines = stdout.split('\n');
                for (const line of lines) {
                    if (line.includes('IPv4') && line.includes('192.168')) {
                        const match = line.match(/(\d+\.\d+\.\d+)\.\d+/);
                        if (match) {
                            resolve(`${match[1]}.0/24`);
                            return;
                        }
                    }
                }
                
                resolve('192.168.1.0/24');
            });
        });
    }

    /**
     * Scan network for active hosts using PowerShell
     */
    async scanNetworkHosts(networkRange) {
        return new Promise((resolve, reject) => {
            console.log(`[CAMERA-DISCOVERY] Scanning hosts: ${networkRange}`);
            
            const baseIp = networkRange.replace('/24', '').replace(/\.\d+$/, '');
            
            // PowerShell command to ping sweep
            const psScript = `
                $results = @()
                1..254 | ForEach-Object -Parallel {
                    $ip = "${baseIp}.$_"
                    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
                        $ip
                    }
                } -ThrottleLimit 50
            `;
            
            // Alternative simpler approach for better compatibility
            const simpleScript = `
                $jobs = @()
                1..254 | ForEach-Object {
                    $ip = "${baseIp}.$_"
                    $jobs += Start-Job -ScriptBlock {
                        param($ip)
                        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) { $ip }
                    } -ArgumentList $ip
                }
                $jobs | Wait-Job -Timeout 30 | Receive-Job
                $jobs | Remove-Job -Force
            `;
            
            // Use fastest approach - simple ping with timeout
            const fastScript = `
                $hosts = @()
                $range = 1..254
                foreach ($i in $range) {
                    $ip = "${baseIp}.$i"
                    $ping = New-Object System.Net.NetworkInformation.Ping
                    try {
                        $result = $ping.Send($ip, 200)
                        if ($result.Status -eq 'Success') {
                            Write-Output $ip
                        }
                    } catch {}
                }
            `;
            
            const child = spawn('powershell', ['-Command', fastScript], {
                shell: true
            });
            
            let output = '';
            let errorOutput = '';
            
            child.stdout.on('data', (data) => {
                output += data.toString();
            });
            
            child.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            
            child.on('close', (code) => {
                const hosts = output
                    .split('\n')
                    .map(line => line.trim())
                    .filter(line => /^\d+\.\d+\.\d+\.\d+$/.test(line));
                
                console.log(`[CAMERA-DISCOVERY] Found ${hosts.length} active hosts`);
                resolve(hosts);
            });
            
            child.on('error', (error) => {
                console.error('[CAMERA-DISCOVERY] Scan error:', error.message);
                resolve([]);
            });
            
            // Timeout after 60 seconds
            setTimeout(() => {
                try {
                    child.kill();
                } catch (e) {}
                resolve([]);
            }, 60000);
        });
    }

    /**
     * Scan specific port on IP
     */
    scanPort(ip, port, timeout = 1000) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            
            socket.setTimeout(timeout);
            
            socket.on('connect', () => {
                socket.destroy();
                resolve(true);
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve(false);
            });
            
            socket.on('error', () => {
                socket.destroy();
                resolve(false);
            });
            
            socket.connect(port, ip);
        });
    }

    /**
     * Scan multiple ports on IP
     */
    async scanPorts(ip, ports = null) {
        ports = ports || this.cameraPorts;
        
        const openPorts = [];
        
        await Promise.all(ports.map(async (port) => {
            const isOpen = await this.scanPort(ip, port);
            if (isOpen) {
                openPorts.push(port);
            }
        }));
        
        return openPorts;
    }

    /**
     * HTTP fingerprint to identify camera manufacturer
     */
    async httpFingerprint(ip, port = 80) {
        return new Promise((resolve) => {
            const request = http.get({
                hostname: ip,
                port: port,
                path: '/',
                timeout: 3000
            }, (response) => {
                const headers = response.headers;
                const server = headers['server'] || '';
                
                let manufacturer = 'Unknown';
                let confidence = 0;
                
                // Check fingerprints
                for (const [key, value] of Object.entries(this.fingerprints)) {
                    if (server.toLowerCase().includes(key)) {
                        manufacturer = value.manufacturer;
                        confidence = value.confidence;
                        break;
                    }
                }
                
                // Collect response body for additional analysis
                let body = '';
                response.on('data', chunk => body += chunk);
                response.on('end', () => {
                    // Check body for hints
                    const bodyLower = body.toLowerCase();
                    for (const [key, value] of Object.entries(this.fingerprints)) {
                        if (bodyLower.includes(key)) {
                            if (value.confidence > confidence) {
                                manufacturer = value.manufacturer;
                                confidence = value.confidence;
                            }
                            break;
                        }
                    }
                    
                    resolve({
                        server,
                        manufacturer,
                        confidence,
                        headers
                    });
                });
            });
            
            request.on('error', () => {
                resolve(null);
            });
            
            request.on('timeout', () => {
                request.destroy();
                resolve(null);
            });
        });
    }

    /**
     * Test RTSP connectivity
     */
    async testRtsp(ip, port = 554) {
        return new Promise((resolve) => {
            const socket = new net.Socket();
            socket.setTimeout(2000);
            
            socket.on('connect', () => {
                // Send RTSP OPTIONS request
                const request = `OPTIONS rtsp://${ip}:${port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n`;
                socket.write(request);
            });
            
            socket.on('data', (data) => {
                const response = data.toString();
                socket.destroy();
                
                if (response.includes('RTSP/1.0 200')) {
                    resolve({ supported: true, response });
                } else {
                    resolve({ supported: true, response }); // RTSP responded
                }
            });
            
            socket.on('timeout', () => {
                socket.destroy();
                resolve({ supported: false });
            });
            
            socket.on('error', () => {
                socket.destroy();
                resolve({ supported: false });
            });
            
            socket.connect(port, ip);
        });
    }

    /**
     * Analyze device and determine if it's a camera
     */
    async analyzeDevice(ip, openPorts) {
        const device = {
            ip,
            ports: openPorts,
            isCamera: false,
            type: 'unknown',
            manufacturer: 'Unknown',
            confidence: 0,
            httpInfo: null,
            rtspSupported: false,
            tuyaPort: openPorts.includes(6668),
            discoveredAt: new Date().toISOString()
        };
        
        // Camera port indicators
        const cameraPortCount = openPorts.filter(p => 
            [554, 6668, 37777, 34567].includes(p)
        ).length;
        
        // HTTP fingerprinting
        if (openPorts.includes(80) || openPorts.includes(8080)) {
            const port = openPorts.includes(80) ? 80 : 8080;
            device.httpInfo = await this.httpFingerprint(ip, port);
            
            if (device.httpInfo) {
                device.manufacturer = device.httpInfo.manufacturer;
                device.confidence = device.httpInfo.confidence;
            }
        }
        
        // RTSP test
        if (openPorts.includes(554)) {
            const rtspResult = await this.testRtsp(ip, 554);
            device.rtspSupported = rtspResult.supported;
            
            if (rtspResult.supported) {
                device.isCamera = true;
                device.confidence = Math.max(device.confidence, 85);
            }
        }
        
        // Tuya detection
        if (openPorts.includes(6668)) {
            device.isCamera = true;
            device.type = 'Tuya/EasyLife Camera';
            device.manufacturer = 'EasyLife/Tuya';
            device.confidence = Math.max(device.confidence, 90);
        }
        
        // Dahua detection
        if (openPorts.includes(37777)) {
            device.isCamera = true;
            device.type = 'Dahua Camera';
            device.manufacturer = 'Dahua';
            device.confidence = Math.max(device.confidence, 95);
        }
        
        // XiongMai detection
        if (openPorts.includes(34567)) {
            device.isCamera = true;
            device.type = 'XiongMai Camera';
            device.manufacturer = 'XiongMai/Generic';
            device.confidence = Math.max(device.confidence, 85);
        }
        
        // Confidence from ports
        if (cameraPortCount >= 2) {
            device.isCamera = true;
            device.confidence = Math.max(device.confidence, 75);
        } else if (cameraPortCount >= 1) {
            device.confidence = Math.max(device.confidence, 50);
        }
        
        // Set type based on analysis
        if (device.isCamera && device.type === 'unknown') {
            if (device.rtspSupported) {
                device.type = 'RTSP Camera';
            } else if (openPorts.includes(80) || openPorts.includes(8080)) {
                device.type = 'IP Camera';
            } else {
                device.type = 'Network Camera';
            }
        }
        
        return device;
    }

    /**
     * Run full passive camera discovery
     */
    async discover(networkRange = null) {
        if (this.isScanning) {
            return { error: 'Scan already in progress' };
        }
        
        this.isScanning = true;
        this.emit('scan:start', { networkRange });
        
        try {
            const startTime = Date.now();
            
            // Get network range if not provided
            if (!networkRange) {
                networkRange = await this.getDefaultNetworkRange();
            }
            
            console.log(`[CAMERA-DISCOVERY] Starting scan: ${networkRange}`);
            
            // Step 1: Discover hosts
            this.emit('scan:progress', { step: 'hosts', message: 'Scanning for active hosts...' });
            const hosts = await this.scanNetworkHosts(networkRange);
            
            if (hosts.length === 0) {
                this.isScanning = false;
                return {
                    success: false,
                    error: 'No active hosts found on network',
                    networkRange
                };
            }
            
            // Step 2: Scan ports on each host
            this.emit('scan:progress', { step: 'ports', message: `Scanning ports on ${hosts.length} hosts...` });
            
            const devicesWithPorts = [];
            
            for (const ip of hosts) {
                const openPorts = await this.scanPorts(ip);
                if (openPorts.length > 0) {
                    devicesWithPorts.push({ ip, ports: openPorts });
                }
            }
            
            // Step 3: Analyze devices
            this.emit('scan:progress', { step: 'analyze', message: `Analyzing ${devicesWithPorts.length} devices...` });
            
            const cameras = [];
            
            for (const device of devicesWithPorts) {
                const analysis = await this.analyzeDevice(device.ip, device.ports);
                if (analysis.isCamera) {
                    cameras.push(analysis);
                    this.emit('camera:found', analysis);
                }
            }
            
            // Compile results
            const elapsed = (Date.now() - startTime) / 1000;
            
            const results = {
                success: true,
                scanTime: new Date().toISOString(),
                networkRange,
                hostsScanned: hosts.length,
                devicesWithPorts: devicesWithPorts.length,
                camerasFound: cameras.length,
                elapsedSeconds: elapsed,
                cameras
            };
            
            // Save results
            const filename = this._saveScanResults(results);
            results.savedTo = filename;
            
            console.log(`[CAMERA-DISCOVERY] Scan complete: ${cameras.length} cameras found in ${elapsed.toFixed(1)}s`);
            
            this.emit('scan:complete', results);
            
            return results;
            
        } catch (error) {
            console.error('[CAMERA-DISCOVERY] Scan error:', error);
            this.emit('scan:error', error);
            return { success: false, error: error.message };
            
        } finally {
            this.isScanning = false;
        }
    }

    /**
     * Quick scan specific IP for camera
     */
    async quickScan(ip) {
        console.log(`[CAMERA-DISCOVERY] Quick scan: ${ip}`);
        
        const openPorts = await this.scanPorts(ip);
        
        if (openPorts.length === 0) {
            return {
                success: false,
                ip,
                error: 'No camera ports open'
            };
        }
        
        const analysis = await this.analyzeDevice(ip, openPorts);
        
        return {
            success: true,
            ...analysis
        };
    }

    /**
     * Run Python discovery script
     */
    async runPythonDiscovery(networkRange = null) {
        return new Promise((resolve, reject) => {
            const scriptPath = path.join(this.scriptsDir, 'cam_discover.py');
            
            if (!fs.existsSync(scriptPath)) {
                reject(new Error('Python discovery script not found'));
                return;
            }
            
            const args = networkRange ? [scriptPath, networkRange] : [scriptPath];
            
            const child = spawn('python', args, {
                cwd: this.scriptsDir
            });
            
            let output = '';
            let errorOutput = '';
            
            child.stdout.on('data', (data) => {
                output += data.toString();
                console.log('[CAMERA-DISCOVERY] Python:', data.toString());
            });
            
            child.stderr.on('data', (data) => {
                errorOutput += data.toString();
            });
            
            child.on('close', (code) => {
                if (code === 0) {
                    // Try to load results from saved file
                    this._loadLastScan();
                    resolve({
                        success: true,
                        output,
                        cameras: this.discoveredCameras
                    });
                } else {
                    reject(new Error(`Script exited with code ${code}: ${errorOutput}`));
                }
            });
            
            child.on('error', (error) => {
                reject(error);
            });
        });
    }

    /**
     * Run Bash discovery script via WSL
     */
    async runBashDiscovery(networkRange = null) {
        return new Promise((resolve, reject) => {
            const scriptPath = path.join(this.scriptsDir, 'find_cams.sh').replace(/\\/g, '/');
            
            // Convert Windows path to WSL path
            const wslPath = scriptPath.replace(/^([A-Za-z]):/, (_, letter) => 
                `/mnt/${letter.toLowerCase()}`
            );
            
            const args = networkRange ? 
                ['wsl', 'bash', wslPath, networkRange] :
                ['wsl', 'bash', wslPath];
            
            console.log(`[CAMERA-DISCOVERY] Running WSL script: ${wslPath}`);
            
            const child = spawn(args[0], args.slice(1), {
                shell: true
            });
            
            let output = '';
            
            child.stdout.on('data', (data) => {
                output += data.toString();
                console.log('[CAMERA-DISCOVERY] WSL:', data.toString());
            });
            
            child.stderr.on('data', (data) => {
                console.error('[CAMERA-DISCOVERY] WSL Error:', data.toString());
            });
            
            child.on('close', (code) => {
                resolve({
                    success: code === 0,
                    output
                });
            });
            
            child.on('error', (error) => {
                // WSL might not be available
                resolve({
                    success: false,
                    error: 'WSL not available: ' + error.message
                });
            });
        });
    }

    /**
     * Get scan status
     */
    getStatus() {
        return {
            isScanning: this.isScanning,
            lastScan: this.lastScan ? {
                time: this.lastScan.scanTime,
                camerasFound: this.lastScan.camerasFound,
                hostsScanned: this.lastScan.hostsScanned
            } : null,
            discoveredCameras: this.discoveredCameras.length,
            cameras: this.discoveredCameras.map(cam => ({
                ip: cam.ip,
                type: cam.type,
                manufacturer: cam.manufacturer,
                confidence: cam.confidence,
                ports: cam.ports
            }))
        };
    }

    /**
     * Get last scan results
     */
    getLastScanResults() {
        return this.lastScan || { cameras: [] };
    }

    /**
     * Clear scan history
     */
    clearHistory() {
        try {
            const files = fs.readdirSync(this.dataDir);
            files.forEach(file => {
                fs.unlinkSync(path.join(this.dataDir, file));
            });
            this.lastScan = null;
            this.discoveredCameras = [];
            return { success: true };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }
}

module.exports = CameraDiscoveryService;
