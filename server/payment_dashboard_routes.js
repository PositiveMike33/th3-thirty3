// ===============================================
// Payment Dashboard Routes - Stats Temps Réel
// ===============================================

const express = require('express');
const router = express.Router();
const { authMiddleware, requireTier } = require('./middleware/auth');
const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

// Dashboard stats - OWNER only
router.get('/dashboard-stats', authMiddleware, requireTier('architect'), async (req, res) => {
    try {
        const stats = {
            stripe: { balance: 0, pending: 0, subscriptions: 0, loading: false },
            paypal: { balance: 0, pending: 0, subscriptions: 0, loading: false },
            total: { revenue: 0, mrr: 0, customers: 0 }
        };

        // Get Stripe stats if configured
        if (process.env.STRIPE_SECRET_KEY) {
            try {
                // Get balance
                const balance = await stripe.balance.retrieve();
                stats.stripe.balance = balance.available[0]?.amount || 0;
                stats.stripe.pending = balance.pending[0]?.amount || 0;

                // Get active subscriptions
                const subscriptions = await stripe.subscriptions.list({ status: 'active', limit: 100 });
                stats.stripe.subscriptions = subscriptions.data.length;

                // Calculate MRR from subscriptions
                let stripeMonthlyRevenue = 0;
                subscriptions.data.forEach(sub => {
                    if (sub.items?.data[0]?.price) {
                        const price = sub.items.data[0].price;
                        if (price.recurring?.interval === 'month') {
                            stripeMonthlyRevenue += price.unit_amount || 0;
                        } else if (price.recurring?.interval === 'year') {
                            stripeMonthlyRevenue += (price.unit_amount || 0) / 12;
                        }
                    }
                });

                stats.total.mrr += stripeMonthlyRevenue;
                stats.total.customers += subscriptions.data.length;
            } catch (stripeError) {
                console.error('[PAYMENT] Stripe API error:', stripeError.message);
                stats.stripe.loading = false;
            }
        }

        // PayPal stats (placeholder - requires PayPal SDK)
        // TODO: Implement when PayPal credentials are configured
        if (process.env.PAYPAL_CLIENT_ID) {
            // Placeholder for now
            stats.paypal.balance = 0;
            stats.paypal.pending = 0;
            stats.paypal.subscriptions = 0;
        }

        // Calculate total revenue (balance + pending)
        stats.total.revenue = stats.stripe.balance + stats.stripe.pending + 
                             stats.paypal.balance + stats.paypal.pending;

        res.json({
            success: true,
            stats,
            last_updated: new Date().toISOString()
        });

    } catch (error) {
        console.error('[PAYMENT] Error getting dashboard stats:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch payment stats'
        });
    }
});

// Get recent transactions
router.get('/recent-transactions', authMiddleware, requireTier('architect'), async (req, res) => {
    try {
        let transactions = [];

        if (process.env.STRIPE_SECRET_KEY) {
            const charges = await stripe.charges.list({ limit: 10 });
            transactions = charges.data.map(charge => ({
                id: charge.id,
                amount: charge.amount,
                currency: charge.currency,
                status: charge.status,
                customer: charge.customer,
                created: charge.created,
                provider: 'stripe',
                description: charge.description
            }));
        }

        res.json({
            success: true,
            transactions
        });

    } catch (error) {
        console.error('[PAYMENT] Error getting transactions:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch transactions'
        });
    }
});

module.exports = router;
