/**
 * Centralized Route Registration
 * All API routes are registered here for cleaner index.js
 */

module.exports = function registerRoutes(app, { requireTier, requireFeature }) {
    // ================================
    // Route Imports
    // ================================

    // Auth & Security
    const authRoutes = require('../auth_routes');
    const securityRoutes = require('../security_routes');
    const securityScannerRoutes = require('../security_scanner_routes');

    // Subscription & Payment
    const subscriptionRoutes = require('../subscription_routes');
    const paymentRoutes = require('../payment_routes');
    const paymentDashboardRoutes = require('../payment_dashboard_routes');

    // AI & Training
    const cyberTrainingRoutes = require('../cyber_training_routes');
    const gpuTrainingRoutes = require('../gpu_training_routes');
    const realTrainingRoutes = require('../real_training_routes');
    const cloudOptimizerRoutes = require('../cloud_optimizer_routes');
    const agentDirectorRoutes = require('../agent_director_routes');

    // Expert Agents
    const expertAgentsRoutes = require('../expert_agents_routes');
    const osintExpertAgentsRoutes = require('../osint_expert_agents_routes');
    const hackingExpertAgentsRoutes = require('../hacking_expert_agents_routes');
    const agentMemoryRoutes = require('../agent_memory_routes');

    // Features
    const dartRoutes = require('./dart');
    const hackerGPTRoutes = require('./hackergpt_routes');
    const trackingRoutes = require('../tracking_routes');
    const kpiDashboardRoutes = require('../kpi_dashboard_routes');
    const orchestratorRoutes = require('../orchestrator_routes');
    const offlineModeRoutes = require('../offline_mode_routes');

    // Network & Security Tools
    const torRoutes = require('../tor_routes');
    const shodanRoutes = require('../shodan_routes');
    const vpnRoutes = require('../vpn_routes');
    const networkRoutes = require('../network_routes');
    const logsRoutes = require('../logs_routes');

    // ================================
    // Health Check (for Docker)
    // ================================
    app.get('/health', (req, res) => {
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            uptime: process.uptime()
        });
    });

    // ================================
    // Public Routes (no auth)
    // ================================
    app.use('/auth', authRoutes);

    // ================================
    // Protected Routes (auth required)
    // ================================

    // Security
    app.use('/api/security', securityRoutes);
    app.use('/api/security-scanner', securityScannerRoutes);

    // Subscription & Payment
    app.use('/api/subscription', subscriptionRoutes);
    app.use('/api/payment', paymentRoutes);
    app.use('/api/payment', paymentDashboardRoutes);

    // Dart
    app.use('/api/dart', dartRoutes);

    // Tracking & Dashboard
    app.use('/api/tracking', trackingRoutes);
    app.use('/api/dashboard', kpiDashboardRoutes);

    // Expert Agents (Free tier)
    app.use('/api/experts', expertAgentsRoutes);
    app.use('/api/agent-memory', agentMemoryRoutes);
    app.use('/api/offline-mode', offlineModeRoutes);

    // ================================
    // Premium Routes (operator+ tier)
    // ================================
    app.use('/api/cyber-training', requireTier('operator'), cyberTrainingRoutes);
    app.use('/api/osint-experts', requireTier('operator'), osintExpertAgentsRoutes);
    app.use('/api/hacking-experts', requireTier('operator'), hackingExpertAgentsRoutes);

    // ================================
    // AI & Training Routes
    // ================================
    app.use('/api/real-training', realTrainingRoutes);
    app.use('/api/gpu-training', gpuTrainingRoutes);
    app.use('/api/cloud-optimizer', cloudOptimizerRoutes);
    app.use('/api/director', agentDirectorRoutes);
    app.use('/api/orchestrator', orchestratorRoutes);

    // ================================
    // Network & Security Tools
    // ================================
    app.use('/api/tor', torRoutes);
    app.use('/api/shodan', shodanRoutes);
    app.use('/api/vpn', vpnRoutes);
    app.use('/api/network', networkRoutes);
    app.use('/api/logs', logsRoutes);
    app.use('/api/hackergpt', hackerGPTRoutes);

    console.log('[ROUTES] All API routes registered');
};
