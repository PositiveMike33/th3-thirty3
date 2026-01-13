require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

(async () => {
    try {
        console.log('Connecting...');
        await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 5000 });
        console.log('Connected.');

        console.log('Creating user...');
        const user = new User({ email: 'test_' + Date.now() + '@example.com' });
        await user.save();
        console.log('User saved:', user._id);

        process.exit(0);
    } catch (err) {
        console.error('Error:', err);
        process.exit(1);
    }
})();
