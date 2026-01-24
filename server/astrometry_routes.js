const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const os = require('os');
const path = require('path');
const AstrometryService = require('./astrometry_service');
const settingsService = require('./settings_service');

const astrometryService = new AstrometryService();
const upload = multer({ dest: os.tmpdir() }); // Temp storage

// Helper to get API Key
function getApiKey() {
    const settings = settingsService.getSettings();
    const key = process.env.ASTROMETRY_API_KEY || (settings.apiKeys && settings.apiKeys.astrometry);
    if (!key) throw new Error('Astrometry.net API Key not configured in Settings');
    return key;
}

// POST /api/astrometry/upload
router.post('/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    try {
        const apiKey = getApiKey();
        const subId = await astrometryService.upload(req.file.path, apiKey);

        // Cleanup temp file
        fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting temp file:", err);
        });

        res.json({ success: true, submission_id: subId });
    } catch (error) {
        console.error("Astrometry Upload Error:", error);
        // Cleanup temp file
        if (req.file && req.file.path) {
            fs.unlink(req.file.path, (e) => { });
        }
        res.status(500).json({ error: error.message });
    }
});

// GET /api/astrometry/status/:id
// ID is the SUBMISSION ID returned by upload
router.get('/status/:id', async (req, res) => {
    const subId = req.params.id;
    try {
        const submission = await astrometryService.getSubmissionStatus(subId);

        // Logical flow to determine unified status
        if (submission.jobs && submission.jobs.length > 0) {
            // We have a job, let's look at the first one (usually 1 image = 1 job)
            const jobId = submission.jobs[0];

            // Check job status if needed, but submission check usually tells us if it's done?
            // Actually submission.job_calibrations is populated if done

            if (submission.job_calibrations && submission.job_calibrations.length > 0) {
                // It's solved!
                const calId = submission.job_calibrations[0]; // usually same as jobId
                // Fetch full calibration details
                const calibration = await astrometryService.getCalibration(jobId); // Assuming jobId is the one

                return res.json({
                    status: 'solved',
                    job_id: jobId,
                    calibration: calibration
                });
            } else if (submission.processing_finished) {
                // Finished but no calibration? -> Failed
                return res.json({ status: 'failed', debug: submission });
            } else {
                return res.json({ status: 'solving', job_id: jobId });
            }

        } else {
            // No job assigned yet
            return res.json({ status: 'uploading' }); // or "queueing"
        }

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
