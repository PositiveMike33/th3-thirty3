const mongoose = require('mongoose');
const User = require('../server/models/User');

const MONGO_URI = 'mongodb://127.0.0.1:27017/th3-thirty3';

mongoose.connect(MONGO_URI)
    .then(async () => {
        console.log("Connected to DB");
        const users = await User.find({}, { email: 1, googleTokens: 1 });
        console.log("Users found:", users.length);
        users.forEach(u => {
            console.log(`User: ${u.email}`);
            console.log(`Has Google Tokens: ${!!u.googleTokens}`);
            if (u.googleTokens) {
                console.log(` - Access Token: ${!!u.googleTokens.access_token}`);
                console.log(` - Refresh Token: ${!!u.googleTokens.refresh_token}`);
                console.log(` - Expiry: ${new Date(u.googleTokens.expiry_date)}`);
            }
            console.log('---');
        });
        process.exit();
    })
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
