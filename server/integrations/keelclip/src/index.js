/**
 * KeelClip VPO Analyzer - Main Entry Point
 * 
 * @module keelclip-vpo-analyzer
 * @version 1.0.0
 * @license Commercial
 */

const express = require('express');
const cors = require('cors');
const VisionService = require('./services/vision');
const AnalyzerService = require('./services/analyzer');
const ValidationService = require('./services/validation');
const logger = require('./utils/logger');
const config = require('./config');

class KeelClipVPOAnalyzer {
    constructor(options = {}) {
        this.config = { ...config, ...options };
        this.app = express();
        this.visionService = new VisionService(this.config);
        this.analyzerService = new AnalyzerService(this.config);
        this.validationService = new ValidationService();
        
        this.setupMiddleware();
        this.setupRoutes();
        
        logger.info('KeelClip VPO Analyzer initialized');
    }

    setupMiddleware() {
        this.app.use(cors());
        this.app.use(express.json({ limit: '50mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));
    }

    setupRoutes() {
        // Health check
        this.app.get('/health', (req, res) => {
            res.json({ status: 'ok', version: '1.0.0' });
        });

        // API Routes
        this.app.post('/api/analyze', this.analyzeIncident.bind(this));
        this.app.post('/api/generate-5why', this.generate5Why.bind(this));
        this.app.post('/api/validate', this.validateReport.bind(this));
        this.app.post('/api/complete', this.completeWorkflow.bind(this));
    }

    /**
     * Analyze incident from image/video
     */
    async analyzeIncident(req, res) {
        try {
            const { media, mediaType = 'image', description = '' } = req.body;
            
            if (!media) {
                return res.status(400).json({ error: 'Media required' });
            }

            logger.info(`Analyzing ${mediaType}...`);
            
            const analysis = await this.visionService.analyzeKeelClipIncident(media, mediaType);
            const summary = this.analyzerService.generateQuickSummary(analysis);

            res.json({
                success: true,
                analysis,
                summary
            });

        } catch (error) {
            logger.error('Analysis failed:', error);
            res.status(500).json({ error: error.message });
        }
    }

    /**
     * Generate 5-Why report
     */
    async generate5Why(req, res) {
        try {
            const { analysis, description = '' } = req.body;
            
            if (!analysis) {
                return res.status(400).json({ error: 'Analysis required' });
            }

            logger.info('Generating 5-Why report...');
            
            const report = await this.analyzerService.generate5Why(analysis, description);
            const validation = this.validationService.validate(report);
            
            logger.info(`Report generated - Score: ${validation.score}/100`);

            res.json({
                success: true,
                report,
                validation
            });

        } catch (error) {
            logger.error('5-Why generation failed:', error);
            res.status(500).json({ error: error.message });
        }
    }

    /**
     * Validate existing report
     */
    validateReport(req, res) {
        try {
            const { report } = req.body;
            
            if (!report) {
                return res.status(400).json({ error: 'Report required' });
            }

            const validation = this.validationService.validate(report);
            
            res.json({
                success: true,
                validation
            });

        } catch (error) {
            logger.error('Validation failed:', error);
            res.status(500).json({ error: error.message });
        }
    }

    /**
     * Complete workflow: Analyze + Generate + Validate
     */
    async completeWorkflow(req, res) {
        try {
            const { media, mediaType = 'image', description = '' } = req.body;
            
            if (!media) {
                return res.status(400).json({ error: 'Media required' });
            }

            logger.info(`Complete workflow: ${mediaType} → 5-Why`);
            
            // Step 1: Vision Analysis
            const analysis = await this.visionService.analyzeKeelClipIncident(media, mediaType);
            logger.info('✓ Vision analysis');

            // Step 2: Generate 5-Why
            const report = await this.analyzerService.generate5Why(analysis, description);
            logger.info('✓ 5-Why generated');

            // Step 3: Validate
            const validation = this.validationService.validate(report);
            logger.info(`✓ Validation: ${validation.score}/100`);

            res.json({
                success: true,
                analysis,
                report,
                validation,
                summary: this.analyzerService.generateQuickSummary(analysis)
            });

        } catch (error) {
            logger.error('Complete workflow failed:', error);
            res.status(500).json({ error: error.message });
        }
    }

    /**
     * Start the server
     */
    start(port = 8080) {
        this.app.listen(port, () => {
            logger.info(`KeelClip VPO Analyzer running on port ${port}`);
            logger.info(`API: http://localhost:${port}/api`);
            logger.info(`Health: http://localhost:${port}/health`);
        });
    }
}

// Export for use as module
module.exports = KeelClipVPOAnalyzer;

// Run as standalone if executed directly
if (require.main === module) {
    const analyzer = new KeelClipVPOAnalyzer();
    analyzer.start(process.env.PORT || 8080);
}
