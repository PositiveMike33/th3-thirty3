// ===============================================
// Payment Routes - Stripe & PayPal Endpoints
// API pour créer sessions paiement et webhooks
// ===============================================

const express = require('express');
const router = express.Router();
const { authMiddleware } = require('./middleware/auth');
const PaymentService = require('./payment_service');

const paymentService = new PaymentService();

// Endpoint public pour obtenir les prix
router.get('/pricing', (req, res) => {
    try {
        const pricing = paymentService.getPricingInfo();
        res.json({
            success: true,
            pricing
        });
    } catch (error) {
        console.error('[PAYMENT] Error getting pricing:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get pricing'
        });
    }
});

// Créer une session de paiement Stripe (authentifié)
router.post('/create-checkout', authMiddleware, async (req, res) => {
    try {
        const { tier, billing_cycle, provider } = req.body;

        if (!tier || !billing_cycle) {
            return res.status(400).json({
                success: false,
                error: 'tier and billing_cycle required'
            });
        }

        if (tier === 'architect') {
            return res.status(400).json({
                success: false,
                error: 'Cannot purchase OWNER tier - reserved for platform owner'
            });
        }

        let result;

        if (provider === 'paypal') {
            result = await paymentService.createPayPalPayment(tier, billing_cycle, req.user);
        } else {
            // Default: Stripe
            result = await paymentService.createStripeCheckoutSession(tier, billing_cycle, req.user);
        }

        res.json(result);
    } catch (error) {
        console.error('[PAYMENT] Error creating checkout:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Webhook Stripe (pas d'auth - vient de Stripe)
router.post('/webhook/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    
    try {
        // Vérifier la signature Stripe
        if (!process.env.STRIPE_SECRET_KEY) {
            console.error('[PAYMENT] STRIPE_SECRET_KEY not configured');
            return res.status(500).json({ error: 'Stripe not configured' });
        }
        const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
        let event;

        try {
            event = stripe.webhooks.constructEvent(
                req.body,
                sig,
                process.env.STRIPE_WEBHOOK_SECRET
            );
        } catch (err) {
            console.error('[PAYMENT] Webhook signature verification failed:', err.message);
            return res.status(400).send(`Webhook Error: ${err.message}`);
        }

        // Traiter l'événement
        const result = await paymentService.handleStripeWebhook(event);

        res.json({ received: true, result });
    } catch (error) {
        console.error('[PAYMENT] Webhook error:', error);
        res.status(500).json({
            success: false,
            error: 'Webhook processing failed'
        });
    }
});

// Webhook PayPal (futur)
router.post('/webhook/paypal', async (req, res) => {
    // TODO: Implémenter PayPal IPN/Webhook
    console.log('[PAYMENT] PayPal webhook received:', req.body);
    res.json({ received: true });
});

module.exports = router;
