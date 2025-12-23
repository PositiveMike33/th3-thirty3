// --- Standalone Verification Script ---
const fs = require('fs');
const path = require('path');

// 1. Mock Stripe BEFORE requiring payment_service
const Module = require('module');
const originalRequire = Module.prototype.require;

Module.prototype.require = function(id) {
    if (id === 'stripe') {
        return () => ({
            checkout: { sessions: { create: async () => ({ id: 'mock_sess', url: 'mock_url' }) } },
            webhooks: { constructEvent: (body) => body } // Simplified mock
        });
    }
    return originalRequire.apply(this, arguments);
};

const PaymentService = require('./payment_service');
const userService = require('./user_service');

async function testFulfillment() {
    console.log('--- STARTING PAYMENT FULFILLMENT TEST (Standalone) ---');

    const paymentService = new PaymentService();
    // Force enable stripe for test even if env var missing
    paymentService.stripeEnabled = true;

    // 1. Create a dummy user for testing
    const testUserId = 'test_user_' + Date.now();
    const testUser = {
        id: testUserId,
        username: 'TestBuyer',
        key: 'test_key',
        tier: 'initiate'
    };

    console.log('1. Creating test user (Initiate)...');
    userService.users.push(testUser);
    userService.saveUsers();

    // Verify user exists and is initiate
    const userBefore = userService.users.find(u => u.id === testUserId);
    console.log(`User created: ${userBefore.username} | Tier: ${userBefore.tier}`);

    if (userBefore.tier !== 'initiate') {
        console.error('❌ Test Setup Failed: User is not initiate');
        return;
    }

    // 2. Simulate Stripe Webhook Event
    console.log('\n2. Simulating Stripe Checkout Completed Webhook (Operator)...');
    const mockEvent = {
        type: 'checkout.session.completed',
        data: {
            object: {
                metadata: {
                    user_id: testUserId,
                    tier: 'operator',
                    username: 'TestBuyer'
                }
            }
        }
    };

    try {
        const result = await paymentService.handleStripeWebhook(mockEvent);
        console.log('Webhook Result:', result);

        // 3. Verify Fulfillment
        console.log('\n3. Verifying User Tier Update...');
        // Reload users from disk to be sure logic persisted it
        userService.loadUsers();
        const userAfter = userService.users.find(u => u.id === testUserId);
        
        console.log(`User status: ${userAfter.username} | Tier: ${userAfter.tier}`);

        if (userAfter.tier === 'operator') {
            console.log('✅ SUCCESS: User verified as OPERATOR. Fulfillment works!');
        } else {
            console.error('❌ FAILURE: User is still ' + userAfter.tier);
        }

    } catch (error) {
        console.error('❌ ERROR during webhook processing:', error);
    } finally {
        // Cleanup
        console.log('\n4. Cleaning up test user...');
        userService.users = userService.users.filter(u => u.id !== testUserId);
        userService.saveUsers();
    }
}

testFulfillment();
