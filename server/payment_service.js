const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;
const paypal = require('@paypal/checkout-server-sdk');
const Transaction = require('./models/Transaction');
const User = require('./models/User');

class PaymentService {
    constructor(socketService) {
        this.socketService = socketService;
        this.stripeEnabled = !!process.env.STRIPE_SECRET_KEY;
        this.paypalEnabled = !!process.env.PAYPAL_CLIENT_ID && !!process.env.PAYPAL_CLIENT_SECRET;

        // PayPal Environment Setup
        if (this.paypalEnabled) {
            try {
                const Environment = process.env.NODE_ENV === 'production'
                    ? paypal.core.LiveEnvironment
                    : paypal.core.SandboxEnvironment;

                this.paypalClient = new paypal.core.PayPalHttpClient(
                    new Environment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
                );
                console.log('[PAYMENT] PayPal Client initialized');
            } catch (err) {
                console.error('[PAYMENT] PayPal Init Failed (Disabling PayPal):', err.message);
                this.paypalEnabled = false;
            }
        }

        // Pricing Configuration
        this.PRICING = {
            pro: {
                monthly: 1999, // Stripe: cents
                paypal: "19.99", // PayPal: string
                currency: 'usd',
                name: 'Pro Plan'
            },
            enterprise: {
                monthly: 9999,
                paypal: "99.99",
                currency: 'usd',
                name: 'Enterprise Plan'
            }
        };
    }

    /**
     * Log transaction to MongoDB
     */
    async logTransaction(data) {
        try {
            const tx = new Transaction(data);
            await tx.save();
            console.log(`[FINANCE] Transaction logged: ${tx.transactionId} (${tx.status})`);
            if (this.socketService) this.socketService.emitTransaction(tx);
            return tx;
        } catch (error) {
            console.error('[FINANCE] Critical Error: Failed to log transaction', error);
        }
    }

    /**
     * Create Stripe Checkout Session
     */
    async createStripeCheckoutSession(tier, billingCycle, user) {
        if (!this.stripeEnabled) throw new Error('Stripe not configured');

        // Simplified pricing logic for MVP
        const plan = this.PRICING[tier];
        if (!plan) throw new Error('Invalid tier');

        try {
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [{
                    price_data: {
                        currency: plan.currency,
                        product_data: { name: plan.name },
                        unit_amount: plan.monthly, // Assuming monthly for now
                    },
                    quantity: 1,
                }],
                mode: 'payment', // 'subscription' requires Price IDs, 'payment' is simpler for One-off
                success_url: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/payment/cancel`,
                client_reference_id: user._id.toString(),
                metadata: {
                    userId: user._id.toString(),
                    tier: tier
                }
            });

            // Log pending transaction
            await this.logTransaction({
                userId: user._id,
                amount: plan.monthly / 100,
                currency: plan.currency,
                provider: 'stripe',
                status: 'pending',
                transactionId: session.id,
                metadata: { tier, sessionUrl: session.url }
            });

            return { url: session.url };
        } catch (error) {
            console.error('[PAYMENT] Stripe Create Error:', error);
            throw error;
        }
    }

    /**
     * Create PayPal Order
     */
    async createPayPalOrder(tier, billingCycle, user) {
        if (!this.paypalEnabled) throw new Error('PayPal not configured');

        const plan = this.PRICING[tier];

        const request = new paypal.orders.OrdersCreateRequest();
        request.prefer("return=representation");
        request.requestBody({
            intent: 'CAPTURE',
            purchase_units: [{
                amount: {
                    currency_code: 'USD',
                    value: plan.paypal
                },
                description: plan.name,
                custom_id: `${user._id}|${tier}`
            }]
        });

        try {
            const order = await this.paypalClient.execute(request);
            const orderId = order.result.id;
            const approveLink = order.result.links.find(link => link.rel === 'approve').href;

            // Log pending
            await this.logTransaction({
                userId: user._id,
                amount: parseFloat(plan.paypal),
                currency: 'usd',
                provider: 'paypal',
                status: 'pending',
                transactionId: orderId,
                metadata: { tier }
            });

            return { orderId, url: approveLink };
        } catch (error) {
            console.error('[PAYMENT] PayPal Create Error:', error);
            throw error;
        }
    }

    /**
     * Capture PayPal Order (Confirmation)
     */
    async capturePayPalOrder(orderId) {
        if (!this.paypalEnabled) throw new Error('PayPal not configured');

        const request = new paypal.orders.OrdersCaptureRequest(orderId);
        request.requestBody({});

        try {
            const capture = await this.paypalClient.execute(request);
            const result = capture.result; // captured order info

            if (result.status === 'COMPLETED') {
                // Update transaction log
                await Transaction.findOneAndUpdate(
                    { transactionId: orderId },
                    { status: 'completed' }
                );

                // TODO: Update user tier in DB logic here or in controller
                return { success: true, status: 'completed' };
            }
            return { success: false, status: result.status };
        } catch (error) {
            console.error('[PAYMENT] PayPal Capture Error:', error);

            await Transaction.findOneAndUpdate(
                { transactionId: orderId },
                { status: 'failed' }
            );
            throw error;
        }
    }

    // --- Helpers ---
    getPricingInfo() {
        return this.PRICING;
    }
}

module.exports = PaymentService;
