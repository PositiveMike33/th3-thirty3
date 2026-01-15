const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const USERS_FILE = path.join(__dirname, '../data/users.json');
const TARGET_EMAIL = 'th3thirty3@gmail.com';
const NEW_PASSWORD = 'Buthaijutsu333!';

async function resetPassword() {
    try {
        if (!fs.existsSync(USERS_FILE)) {
            console.error('Users file not found!');
            process.exit(1);
        }

        const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
        const users = data.users || [];

        const user = users.find(u => u.email === TARGET_EMAIL);

        if (!user) {
            console.error(`User ${TARGET_EMAIL} not found!`);
            process.exit(1);
        }

        console.log(`Found user: ${user.username}`);

        const hashedPassword = await bcrypt.hash(NEW_PASSWORD, 10);
        user.password = hashedPassword;

        fs.writeFileSync(USERS_FILE, JSON.stringify({ users }, null, 2));

        console.log('✅ Password reset successfully!');
        console.log(`Email: ${TARGET_EMAIL}`);
        console.log(`Password: ${NEW_PASSWORD}`);

        // Verify immediately
        const verify = await bcrypt.compare(NEW_PASSWORD, hashedPassword);
        console.log(`Immediate Bytecode Verify Check: ${verify}`);
        if (!verify) console.error("WTF: Hash generation failed immediately?");


    } catch (error) {
        console.error('Error:', error);
    }
}

resetPassword();
