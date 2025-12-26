/**
 * OSINT STARTUP CHECK
 * ====================
 * Tests all OSINT tools and services on server startup
 * Ensures everything is ready for operation
 */

const http = require('http');
const https = require('https');

class OsintStartupCheck {
    constructor(baseUrl = 'http://localhost:3000') {
        this.baseUrl = baseUrl;
        this.results = {
            timestamp: new Date().toISOString(),
            passed: 0,
            failed: 0,
            warnings: 0,
            tests: []
        };
        
        // OSINT endpoints to test
        this.osintEndpoints = [
            { name: 'IP Location', path: '/api/iplocation/lookup?ip=8.8.8.8', method: 'GET' },
            { name: 'IP2Location', path: '/api/ip2location/lookup?ip=8.8.8.8', method: 'GET' },
            { name: 'WHOIS Domain', path: '/api/whois/lookup?domain=google.com', method: 'GET' },
            { name: 'Shodan Status', path: '/api/shodan/status', method: 'GET' },
            { name: 'Network Scanner Status', path: '/api/network/status', method: 'GET' },
            { name: 'OSINT Tools List', path: '/osint/tools', method: 'GET' },
            { name: 'TOR Status', path: '/api/tor/status', method: 'GET' },
            { name: 'VPN Status', path: '/api/vpn/status', method: 'GET' },
            { name: 'Camera Discovery', path: '/api/camera-discovery/status', method: 'GET' }
        ];
        
        // Core services to verify
        this.coreServices = [
            { name: 'LLM Models', path: '/models', method: 'GET' },
            { name: 'Fibonacci Cognitive', path: '/models/metrics', method: 'GET' },
            { name: 'Director Agents', path: '/api/director/status', method: 'GET' },
            { name: 'Google Services', path: '/api/google/status', method: 'GET' },
            { name: 'Auth Status', path: '/auth/status', method: 'GET' }
        ];
    }

    async fetch(path, options = {}) {
        return new Promise((resolve, reject) => {
            const url = new URL(path, this.baseUrl);
            const client = url.protocol === 'https:' ? https : http;
            
            const req = client.get(url.toString(), { timeout: 10000 }, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        resolve({ 
                            status: res.statusCode, 
                            data: JSON.parse(data),
                            ok: res.statusCode >= 200 && res.statusCode < 300
                        });
                    } catch {
                        resolve({ 
                            status: res.statusCode, 
                            data: data,
                            ok: res.statusCode >= 200 && res.statusCode < 300
                        });
                    }
                });
            });
            
            req.on('error', (e) => reject(e));
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Timeout'));
            });
        });
    }

    async testEndpoint(endpoint) {
        const startTime = Date.now();
        try {
            const res = await this.fetch(endpoint.path);
            const duration = Date.now() - startTime;
            
            if (res.ok) {
                return {
                    name: endpoint.name,
                    status: 'PASS',
                    code: res.status,
                    duration: `${duration}ms`,
                    details: this.extractDetails(res.data)
                };
            } else {
                return {
                    name: endpoint.name,
                    status: 'WARN',
                    code: res.status,
                    duration: `${duration}ms`,
                    details: 'Non-200 response'
                };
            }
        } catch (error) {
            return {
                name: endpoint.name,
                status: 'FAIL',
                error: error.message,
                duration: `${Date.now() - startTime}ms`
            };
        }
    }

    extractDetails(data) {
        if (!data || typeof data !== 'object') return 'OK';
        
        // Extract useful info based on response type
        if (data.models) return `${data.models.length} models`;
        if (data.agents) return `${data.agents.length} agents`;
        if (data.tools) return `${data.tools.length} tools`;
        if (data.ip) return `IP: ${data.ip}`;
        if (data.domain) return `Domain: ${data.domain}`;
        if (data.country) return `Country: ${data.country}`;
        if (data.success !== undefined) return data.success ? 'Active' : 'Inactive';
        if (data.connected !== undefined) return data.connected ? 'Connected' : 'Disconnected';
        
        return 'OK';
    }

    async runAllTests() {
        console.log('\n' + '═'.repeat(60));
        console.log('  🔍 OSINT STARTUP CHECK - Th3 Thirty3');
        console.log('  ' + new Date().toLocaleString());
        console.log('═'.repeat(60) + '\n');

        // Test Core Services
        console.log('📡 CORE SERVICES');
        console.log('─'.repeat(40));
        for (const endpoint of this.coreServices) {
            const result = await this.testEndpoint(endpoint);
            this.logResult(result);
            this.results.tests.push(result);
            this.updateCounts(result);
        }

        console.log('\n🛡️  OSINT TOOLS');
        console.log('─'.repeat(40));
        for (const endpoint of this.osintEndpoints) {
            const result = await this.testEndpoint(endpoint);
            this.logResult(result);
            this.results.tests.push(result);
            this.updateCounts(result);
        }

        this.printSummary();
        return this.results;
    }

    logResult(result) {
        const icon = result.status === 'PASS' ? '✅' : 
                     result.status === 'WARN' ? '⚠️' : '❌';
        const details = result.details || result.error || '';
        console.log(`  ${icon} ${result.name.padEnd(22)} ${result.status.padEnd(6)} ${result.duration.padStart(8)}  ${details}`);
    }

    updateCounts(result) {
        if (result.status === 'PASS') this.results.passed++;
        else if (result.status === 'WARN') this.results.warnings++;
        else this.results.failed++;
    }

    printSummary() {
        const total = this.results.passed + this.results.warnings + this.results.failed;
        const passRate = ((this.results.passed / total) * 100).toFixed(1);
        
        console.log('\n' + '═'.repeat(60));
        console.log('  📊 SUMMARY');
        console.log('─'.repeat(60));
        console.log(`  ✅ Passed:   ${this.results.passed}`);
        console.log(`  ⚠️  Warnings: ${this.results.warnings}`);
        console.log(`  ❌ Failed:   ${this.results.failed}`);
        console.log(`  📈 Pass Rate: ${passRate}%`);
        console.log('═'.repeat(60));
        
        if (this.results.failed === 0) {
            console.log('\n  🎉 ALL OSINT SYSTEMS OPERATIONAL!\n');
        } else {
            console.log('\n  ⚠️  Some systems need attention.\n');
        }
    }

    // Quick health check (for startup)
    async quickCheck() {
        console.log('[OSINT] Running startup health check...');
        
        const criticalEndpoints = [
            { name: 'Server', path: '/health', method: 'GET' },
            { name: 'Models', path: '/models/list', method: 'GET' }
        ];
        
        let allOk = true;
        for (const endpoint of criticalEndpoints) {
            try {
                const res = await this.fetch(endpoint.path);
                if (!res.ok) allOk = false;
            } catch {
                allOk = false;
            }
        }
        
        console.log(`[OSINT] Health check: ${allOk ? 'OK' : 'ISSUES DETECTED'}`);
        return allOk;
    }
}

// Export for use in server startup
module.exports = OsintStartupCheck;

// Run if called directly
if (require.main === module) {
    const checker = new OsintStartupCheck();
    checker.runAllTests()
        .then(results => {
            process.exit(results.failed > 0 ? 1 : 0);
        })
        .catch(err => {
            console.error('Check failed:', err);
            process.exit(1);
        });
}
