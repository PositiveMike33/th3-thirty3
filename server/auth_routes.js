// ===============================================
// Auth Routes - Login, Register, Profile API
// ===============================================

const express = require('express');
const router = express.Router();
const authService = require('./auth_service');

/**
 * GET /auth/status
 * Health check - returns auth service status (no auth required)
 */
router.get('/status', (req, res) => {
    try {
        // Check if auth service is operational
        const usersLoaded = authService.users ? authService.users.length : 0;
        
        res.json({
            success: true,
            status: 'operational',
            authenticated: false, // Will be updated by middleware if token present
            usersCount: usersLoaded,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            status: 'error',
            error: error.message
        });
    }
});

/**
 * POST /auth/register
 * Create a new user account
 */
router.post('/register', async (req, res) => {
    try {
        const { username, email, password, firstName, lastName } = req.body;

        const result = await authService.register(
            username,
            email,
            password,
            firstName,
            lastName
        );

        res.status(201).json({
            success: true,
            message: 'Account created successfully',
            ...result
        });
    } catch (error) {
        console.error('[AUTH] Registration error:', error.message);
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /auth/login
 * Authenticate user and return token
 */
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await authService.login(email, password);

        res.json({
            success: true,
            message: 'Login successful',
            ...result
        });
    } catch (error) {
        console.error('[AUTH] Login error:', error.message);
        res.status(401).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * GET /auth/me
 * Get current user from token
 */
router.get('/me', (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'No token provided'
            });
        }

        const token = authHeader.split(' ')[1];
        const user = authService.verifyToken(token);

        res.json({
            success: true,
            user
        });
    } catch (error) {
        res.status(401).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * PUT /auth/profile
 * Update user profile
 */
router.put('/profile', (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'No token provided'
            });
        }

        const token = authHeader.split(' ')[1];
        const currentUser = authService.verifyToken(token);

        const updatedUser = authService.updateProfile(currentUser.id, req.body);

        res.json({
            success: true,
            message: 'Profile updated',
            user: updatedUser
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /auth/change-password
 * Change user password
 */
router.post('/change-password', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'No token provided'
            });
        }

        const token = authHeader.split(' ')[1];
        const currentUser = authService.verifyToken(token);

        const { oldPassword, newPassword } = req.body;

        await authService.changePassword(currentUser.id, oldPassword, newPassword);

        res.json({
            success: true,
            message: 'Password changed successfully'
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
});

/**
 * POST /auth/verify
 * Verify if token is still valid
 */
router.post('/verify', (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({
                success: false,
                error: 'Token required'
            });
        }

        const user = authService.verifyToken(token);

        res.json({
            success: true,
            valid: true,
            user
        });
    } catch (error) {
        res.json({
            success: true,
            valid: false,
            error: error.message
        });
    }
});

/**
 * POST /auth/logout
 * Logout (client-side token removal, server just acknowledges)
 */
router.post('/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

module.exports = router;
