/**
 * Nexus33 Security Setup Script
 * Run this script to secure your production deployment
 * 
 * Usage: node server/scripts/secure_production.js
 */

const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const ENV_FILE = path.join(__dirname, '..', '..', '.env');
const ENV_EXAMPLE_FILE = path.join(__dirname, '..', '..', '.env.production.example');

// Colors for terminal
const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    cyan: '\x1b[36m'
};

const log = {
    info: (msg) => console.log(`${colors.cyan}[INFO]${colors.reset} ${msg}`),
    success: (msg) => console.log(`${colors.green}[SUCCESS]${colors.reset} ${msg}`),
    warning: (msg) => console.log(`${colors.yellow}[WARNING]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[ERROR]${colors.reset} ${msg}`),
    header: (msg) => console.log(`\n${colors.blue}═══════════════════════════════════════════════${colors.reset}\n${colors.blue}  ${msg}${colors.reset}\n${colors.blue}═══════════════════════════════════════════════${colors.reset}\n`)
};

// Generate secure random string
function generateSecureKey(length = 64) {
    return crypto.randomBytes(length).toString('base64');
}

// Generate secure API key
function generateApiKey() {
    return `sk-${crypto.randomBytes(32).toString('hex')}`;
}

// Hash password
async function hashPassword(password) {
    return bcrypt.hash(password, 12);
}

// Create readline interface for user input
function createPrompt() {
    return readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
}

// Ask question
function ask(rl, question) {
    return new Promise(resolve => {
        rl.question(question, answer => resolve(answer));
    });
}

// Main security setup
async function secureProduction() {
    log.header('NEXUS33 PRODUCTION SECURITY SETUP');

    const rl = createPrompt();

    try {
        // 1. Generate new JWT Secret
        log.info('Generating new JWT Secret...');
        const newJwtSecret = generateSecureKey(64);
        log.success(`JWT Secret generated (${newJwtSecret.length} characters)`);

        // 2. Get new admin password
        console.log('');
        const newAdminPassword = await ask(rl, `${colors.cyan}Enter new admin password (min 12 chars): ${colors.reset}`);
        
        if (newAdminPassword.length < 12) {
            log.error('Password must be at least 12 characters!');
            rl.close();
            process.exit(1);
        }

        // Validate password strength
        const hasUppercase = /[A-Z]/.test(newAdminPassword);
        const hasLowercase = /[a-z]/.test(newAdminPassword);
        const hasNumber = /[0-9]/.test(newAdminPassword);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(newAdminPassword);

        if (!(hasUppercase && hasLowercase && hasNumber)) {
            log.warning('Password should contain uppercase, lowercase, and numbers');
        }

        const passwordHash = await hashPassword(newAdminPassword);
        log.success('Admin password hashed with bcrypt (12 rounds)');

        // 3. Generate new API key
        const newApiKey = generateApiKey();
        log.success('New API key generated');

        // 4. Update users.json
        log.info('Updating admin credentials...');
        
        if (fs.existsSync(USERS_FILE)) {
            const usersData = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
            
            // Find and update admin user
            const adminIndex = usersData.users.findIndex(u => 
                u.tier === 'architect' || u.tier === 'admin' || u.email === 'admin@nexus33.io'
            );

            if (adminIndex !== -1) {
                usersData.users[adminIndex].password = passwordHash;
                usersData.users[adminIndex].key = newApiKey;
                usersData.users[adminIndex].securityUpdatedAt = new Date().toISOString();
                
                fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
                log.success('Admin credentials updated in users.json');
            } else {
                log.warning('No admin user found - creating new admin');
                usersData.users.push({
                    id: 'admin-secure-001',
                    username: 'admin',
                    email: 'admin@nexus33.io',
                    password: passwordHash,
                    tier: 'architect',
                    key: newApiKey,
                    createdAt: new Date().toISOString(),
                    profile: {
                        firstName: 'Admin',
                        lastName: 'Nexus33',
                        bio: 'System Administrator'
                    }
                });
                fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2));
            }
        }

        // 5. Update .env file
        log.info('Updating .env file...');
        
        let envContent = '';
        if (fs.existsSync(ENV_FILE)) {
            envContent = fs.readFileSync(ENV_FILE, 'utf8');
        }

        // Update or add JWT_SECRET
        if (envContent.includes('JWT_SECRET=')) {
            envContent = envContent.replace(/JWT_SECRET=.*/g, `JWT_SECRET=${newJwtSecret}`);
        } else {
            envContent += `\n# Security (Generated ${new Date().toISOString()})\nJWT_SECRET=${newJwtSecret}\n`;
        }

        // Add NODE_ENV if not present
        if (!envContent.includes('NODE_ENV=')) {
            envContent = `NODE_ENV=production\n` + envContent;
        }

        fs.writeFileSync(ENV_FILE, envContent);
        log.success('.env file updated with new JWT_SECRET');

        // 6. Create production .env example
        const envExample = `# Nexus33 Production Environment
# Copy this file to .env and fill in the values

NODE_ENV=production

# Server
PORT=3000
API_BASE_URL=https://api.nexus33.io
FRONTEND_URL=https://nexus33.io
CORS_ORIGINS=https://nexus33.io,https://www.nexus33.io

# Authentication (CRITICAL - Keep secret!)
JWT_SECRET=<generate-with-secure_production.js>

# Database
MONGODB_URI=mongodb+srv://user:password@cluster.mongodb.net/nexus33

# Ollama (Local AI)
OLLAMA_BASE_URL=http://localhost:11434

# Payments
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx

# AI Providers
OPENAI_API_KEY=sk-xxx
ANTHROPIC_API_KEY=sk-ant-xxx
GEMINI_API_KEY=xxx

# Security Services
SHODAN_API_KEY=xxx

# Email
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=xxx
SMTP_PASS=xxx
`;

        fs.writeFileSync(ENV_EXAMPLE_FILE, envExample);
        log.success('Created .env.production.example template');

        // 7. Print summary
        log.header('SECURITY SETUP COMPLETE');
        
        console.log(`${colors.green}New Admin Credentials:${colors.reset}`);
        console.log(`  Email:    admin@nexus33.io`);
        console.log(`  Password: ${colors.yellow}(the one you entered)${colors.reset}`);
        console.log(`  API Key:  ${colors.cyan}${newApiKey}${colors.reset}`);
        console.log('');
        console.log(`${colors.yellow}IMPORTANT: Save these credentials securely!${colors.reset}`);
        console.log(`${colors.yellow}The password is NOT stored in plain text.${colors.reset}`);
        console.log('');
        console.log(`${colors.green}Next Steps:${colors.reset}`);
        console.log('  1. Restart the server: npm run start');
        console.log('  2. Test login with new credentials');
        console.log('  3. Store API key in password manager');
        console.log('  4. Never commit .env to git');

        rl.close();
        
    } catch (error) {
        log.error(`Setup failed: ${error.message}`);
        rl.close();
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    secureProduction();
}

module.exports = { generateSecureKey, generateApiKey, hashPassword };
