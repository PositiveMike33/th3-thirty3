// ===============================================
// Auth Service - JWT Authentication & User Management
// Secure login, registration, and session management
// ===============================================

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'nexus33-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d';

class AuthService {
    constructor() {
        this.users = [];
        this.loadUsers();
        console.log('[AUTH] Service initialized');
    }

    loadUsers() {
        try {
            if (fs.existsSync(USERS_FILE)) {
                const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
                this.users = data.users || [];
                console.log(`[AUTH] Loaded ${this.users.length} users`);
            } else {
                // Create default admin user
                this.users = [{
                    id: 'admin-001',
                    username: 'admin',
                    email: 'admin@nexus33.io',
                    password: bcrypt.hashSync('admin123', 10),
                    tier: 'architect',
                    key: 'sk-ADMIN-TH3-THIRTY3-MASTER-KEY',
                    createdAt: new Date().toISOString(),
                    profile: {
                        firstName: 'Admin',
                        lastName: 'Nexus33',
                        avatar: null
                    }
                }];
                this.saveUsers();
                console.log('[AUTH] Created default admin user');
            }
        } catch (error) {
            console.error('[AUTH] Failed to load users:', error);
            this.users = [];
        }
    }

    saveUsers() {
        try {
            const dir = path.dirname(USERS_FILE);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
            fs.writeFileSync(USERS_FILE, JSON.stringify({ users: this.users }, null, 2));
            return true;
        } catch (error) {
            console.error('[AUTH] Failed to save users:', error);
            return false;
        }
    }

    /**
     * Register a new user
     */
    async register(username, email, password, firstName = '', lastName = '') {
        // Validation
        if (!username || !email || !password) {
            throw new Error('Username, email, and password are required');
        }

        if (password.length < 6) {
            throw new Error('Password must be at least 6 characters');
        }

        // Check if user exists
        const existingUser = this.users.find(u => 
            u.email.toLowerCase() === email.toLowerCase() || 
            u.username.toLowerCase() === username.toLowerCase()
        );

        if (existingUser) {
            throw new Error('User with this email or username already exists');
        }

        // Create new user
        const hashedPassword = await bcrypt.hash(password, 12);
        const apiKey = `sk-${uuidv4().replace(/-/g, '').substring(0, 32)}`;

        const newUser = {
            id: uuidv4(),
            username: username.toLowerCase(),
            email: email.toLowerCase(),
            password: hashedPassword,
            tier: 'initiate', // Free tier by default
            key: apiKey,
            createdAt: new Date().toISOString(),
            lastLogin: null,
            profile: {
                firstName,
                lastName,
                avatar: null,
                bio: ''
            },
            settings: {
                theme: 'dark',
                notifications: true,
                language: 'fr'
            },
            usage: {
                chatCount: 0,
                searchCount: 0,
                lastActive: null
            }
        };

        this.users.push(newUser);
        this.saveUsers();

        console.log(`[AUTH] New user registered: ${username} (${email})`);

        // Generate token
        const token = this.generateToken(newUser);

        return {
            user: this.sanitizeUser(newUser),
            token
        };
    }

    /**
     * Login user
     */
    async login(emailOrUsername, password) {
        if (!emailOrUsername || !password) {
            throw new Error('Email/username and password are required');
        }

        // Find user
        const user = this.users.find(u => 
            u.email.toLowerCase() === emailOrUsername.toLowerCase() ||
            u.username.toLowerCase() === emailOrUsername.toLowerCase()
        );

        if (!user) {
            throw new Error('Invalid credentials');
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            throw new Error('Invalid credentials');
        }

        // Update last login
        user.lastLogin = new Date().toISOString();
        user.usage.lastActive = new Date().toISOString();
        this.saveUsers();

        console.log(`[AUTH] User logged in: ${user.username}`);

        // Generate token
        const token = this.generateToken(user);

        return {
            user: this.sanitizeUser(user),
            token
        };
    }

    /**
     * Verify JWT token and return user
     */
    verifyToken(token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = this.users.find(u => u.id === decoded.userId);
            
            if (!user) {
                throw new Error('User not found');
            }

            return this.sanitizeUser(user);
        } catch (error) {
            throw new Error('Invalid or expired token');
        }
    }

    /**
     * Get user by ID
     */
    getUserById(userId) {
        const user = this.users.find(u => u.id === userId);
        return user ? this.sanitizeUser(user) : null;
    }

    /**
     * Update user profile
     */
    updateProfile(userId, updates) {
        const userIndex = this.users.findIndex(u => u.id === userId);
        if (userIndex === -1) {
            throw new Error('User not found');
        }

        const allowedUpdates = ['firstName', 'lastName', 'bio', 'avatar'];
        const profileUpdates = {};

        for (const key of allowedUpdates) {
            if (updates[key] !== undefined) {
                profileUpdates[key] = updates[key];
            }
        }

        this.users[userIndex].profile = {
            ...this.users[userIndex].profile,
            ...profileUpdates
        };

        this.saveUsers();
        return this.sanitizeUser(this.users[userIndex]);
    }

    /**
     * Change password
     */
    async changePassword(userId, oldPassword, newPassword) {
        const user = this.users.find(u => u.id === userId);
        if (!user) {
            throw new Error('User not found');
        }

        const isValid = await bcrypt.compare(oldPassword, user.password);
        if (!isValid) {
            throw new Error('Current password is incorrect');
        }

        if (newPassword.length < 6) {
            throw new Error('New password must be at least 6 characters');
        }

        user.password = await bcrypt.hash(newPassword, 12);
        this.saveUsers();

        console.log(`[AUTH] Password changed for: ${user.username}`);
        return true;
    }

    /**
     * Generate JWT token
     */
    generateToken(user) {
        return jwt.sign(
            { 
                userId: user.id,
                username: user.username,
                tier: user.tier
            },
            JWT_SECRET,
            { expiresIn: JWT_EXPIRES_IN }
        );
    }

    /**
     * Remove sensitive data from user object
     */
    sanitizeUser(user) {
        const { password, key, ...safeUser } = user;
        return safeUser;
    }

    /**
     * Get all users (admin only)
     */
    getAllUsers() {
        return this.users.map(u => this.sanitizeUser(u));
    }

    /**
     * Delete user
     */
    deleteUser(userId) {
        const index = this.users.findIndex(u => u.id === userId);
        if (index === -1) {
            throw new Error('User not found');
        }

        const user = this.users[index];
        this.users.splice(index, 1);
        this.saveUsers();

        console.log(`[AUTH] User deleted: ${user.username}`);
        return true;
    }
}

module.exports = new AuthService();
