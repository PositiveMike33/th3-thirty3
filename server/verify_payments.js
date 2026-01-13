require('dotenv').config();
const mongoose = require('mongoose');
const PaymentService = require('./payment_service');
const User = require('./models/User');
const Transaction = require('./models/Transaction');

const runTest = async () => {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(process.env.MONGODB_URI);
        console.log('✅ Connected.');

        const paymentService = new PaymentService();

        // Create Dummy User
        const user = new User({
            email: `paytest_${Date.now()}@test.com`,
            name: 'Payment Tester'
        });
        await user.save();
        console.log(`👤 Dummy User Created: ${user._id}`);

        // 1. Test Stripe
        if (paymentService.stripeEnabled) {
            console.log('\n💳 Testing Stripe Checkout...');
            const session = await paymentService.createStripeCheckoutSession('pro', 'monthly', user);
            console.log(`✅ Stripe Session Created: ${session.url.substring(0, 50)}...`);

            // Verify DB Log
            const log = await Transaction.findOne({ provider: 'stripe', userId: user._id });
            if (!log) throw new Error('Stripe Transaction not logged to DB');
            console.log(`✅ Transaction Logged: ${log.transactionId}`);
        } else {
            console.log('⚠️ Stripe disabled (Skipping)');
        }

        // 2. Test PayPal
        if (paymentService.paypalEnabled) {
            console.log('\n🅿️ Testing PayPal Order...');
            try {
                const order = await paymentService.createPayPalOrder('pro', 'monthly', user);
                console.log(`✅ PayPal Order Created: ${order.orderId}`);

                // Verify DB Log
                const log = await Transaction.findOne({ provider: 'paypal', userId: user._id });
                if (!log) throw new Error('PayPal Transaction not logged to DB');
                console.log(`✅ Transaction Logged: ${log.transactionId}`);
            } catch (err) {
                console.error('❌ PayPal Test Failed:', err.message);
                if (err.response) console.error('PayPal Details:', JSON.stringify(err.response, null, 2));
            }
        } else {
            console.log('⚠️ PayPal disabled (Skipping)');
        }

        // Cleanup
        console.log('\n🧹 Cleaning up...');
        await User.findByIdAndDelete(user._id);
        await Transaction.deleteMany({ userId: user._id });
        console.log('✅ Cleaned up.');

        // Success if at least Stripe worked (Critical path)
        if (paymentService.stripeEnabled) {
            console.log('✅ Payment System Verified (Stripe Operational)');
            process.exit(0);
        } else {
            console.error('❌ Payment System Failed: No active providers');
            process.exit(1);
        }
    } catch (error) {
        console.error('\n❌ CRITICAL TEST FAILURE:', error);
        process.exit(1);
    }
};

runTest();
