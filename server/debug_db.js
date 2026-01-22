const fs = require('fs');
const mongoose = require('mongoose');
const User = require('./models/User');

const MONGO_URI = 'mongodb://127.0.0.1:27017/th3-thirty3';

mongoose.connect(MONGO_URI)
    .then(async () => {
        let output = "Connected to DB\n";
        const users = await User.find({}, { email: 1, googleTokens: 1 });
        output += `Users found: ${users.length}\n`;
        users.forEach(u => {
            output += `User: ${u.email}\n`;
            output += `Has Google Tokens: ${!!u.googleTokens}\n`;
            if (u.googleTokens) {
                output += ` - Access Token: ${!!u.googleTokens.access_token}\n`;
                output += ` - Refresh Token: ${!!u.googleTokens.refresh_token}\n`;
                output += ` - Expiry: ${new Date(u.googleTokens.expiry_date)}\n`;
            }
            output += '---\n';
        });
        fs.writeFileSync('debug_db_output.txt', output);
        console.log("Done writing to debug_db_output.txt");
        process.exit();
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
