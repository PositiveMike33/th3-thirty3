// ===============================================
// Payment Service - Stripe & PayPal Integration
// Gestion des paiements d'abonnements
// ===============================================

const stripe = process.env.STRIPE_SECRET_KEY ? require('stripe')(process.env.STRIPE_SECRET_KEY) : null;

class PaymentService {
    constructor() {
        this.stripeEnabled = !!process.env.STRIPE_SECRET_KEY;
        this.paypalEnabled = !!process.env.PAYPAL_CLIENT_ID && !!process.env.PAYPAL_CLIENT_SECRET;
        
        // Prix des tiers (en cents pour Stripe)
        this.PRICING = {
            operator: {
                monthly: 1999, // 19.99$
                yearly: 19990, // 199.90$ (2 mois gratuits)
                currency: 'usd',
                name: 'Premium Monthly',
                features: [
                    'Chat illimité',
                    'Tous les modèles cloud (Groq, OpenAI)',
                    'OSINT complet (basique + avancé)',
                    'Hacking tools',
                    'Cyber Training',
                    '10 agents spécialisés',
                    'Tous les patterns Fabric'
                ]
            },
            enterprise: {
                monthly: 9999, // 99.99$
                yearly: 99990, // 999.90$ (2 mois gratuits)
                currency: 'usd',
                name: 'Enterprise Monthly',
                features: [
                    'Tout de Premium +',
                    '25 agents spécialisés',
                    '10 sièges utilisateurs',
                    'Support prioritaire',
                    'SLA garanti',
                    'Personnalisation'
                ]
            }
        };

        if (this.stripeEnabled) {
            console.log('[PAYMENT] Stripe initialized');
        }
        if (this.paypalEnabled) {
            console.log('[PAYMENT] PayPal initialized');
        }
    }

    /**
     * Créer une session de paiement Stripe
     * @param {String} tier - Tier ciblé (operator, enterprise)
     * @param {String} billingCycle - monthly ou yearly
     * @param {Object} user - Utilisateur
     * @returns {Object} - Session Stripe avec URL de paiement
     */
    async createStripeCheckoutSession(tier, billingCycle, user) {
        if (!this.stripeEnabled) {
            throw new Error('Stripe is not configured');
        }

        const pricing = this.PRICING[tier];
        if (!pricing) {
            throw new Error(`Invalid tier: ${tier}`);
        }

        const amount = pricing[billingCycle];
        if (!amount) {
            throw new Error(`Invalid billing cycle: ${billingCycle}`);
        }

        try {
            const session = await stripe.checkout.sessions.create({
                payment_method_types: ['card'],
                line_items: [
                    {
                        price_data: {
                            currency: pricing.currency,
                            product_data: {
                                name: `${pricing.name} - ${billingCycle === 'yearly' ? 'Yearly' : 'Monthly'}`,
                                description: pricing.features.join(', ')
                            },
                            unit_amount: amount,
                            recurring: {
                                interval: billingCycle === 'yearly' ? 'year' : 'month'
                            }
                        },
                        quantity: 1
                    }
                ],
                mode: 'subscription',
                success_url: `${process.env.FRONTEND_URL}/subscription/success?session_id={CHECKOUT_SESSION_ID}`,
                cancel_url: `${process.env.FRONTEND_URL}/subscription/canceled`,
                client_reference_id: user.id,
                metadata: {
                    user_id: user.id,
                    username: user.username,
                    tier: tier,
                    billing_cycle: billingCycle
                }
            });

            console.log(`[PAYMENT] Stripe session created for ${user.username} - ${tier} ${billingCycle}`);

            return {
                success: true,
                provider: 'stripe',
                session_id: session.id,
                url: session.url
            };
        } catch (error) {
            console.error('[PAYMENT] Stripe error:', error);
            throw error;
        }
    }

    /**
     * Créer un lien de paiement PayPal
     * @param {String} tier - Tier ciblé
     * @param {String} billingCycle - monthly ou yearly
     * @param {Object} user - Utilisateur
     * @returns {Object} - Lien PayPal
     */
    async createPayPalPayment(tier, billingCycle, user) {
        if (!this.paypalEnabled) {
            throw new Error('PayPal is not configured');
        }

        const pricing = this.PRICING[tier];
        if (!pricing) {
            throw new Error(`Invalid tier: ${tier}`);
        }

        // PayPal SDK nécessiterait @paypal/checkout-server-sdk
        // Pour simplifier, on retourne une URL de subscription PayPal
        // Dans un vrai système, utiliser PayPal REST API v2

        return {
            success: true,
            provider: 'paypal',
            message: 'PayPal integration coming soon',
            manual_setup_required: true,
            instructions: `
                1. Créer un bouton d'abonnement sur PayPal.com
                2. Configurer le montant: ${(pricing[billingCycle] / 100).toFixed(2)} USD
                3. Définir la fréquence: ${billingCycle}
                4. Copier le code du bouton
            `
        };
    }

    /**
     * Vérifier le webhoo Stripe
     * @param {Object} event - Événement Stripe
     * @returns {Object} - Résultat du traitement
     */
    async handleStripeWebhook(event) {
        console.log(`[PAYMENT] Stripe webhook: ${event.type}`);

        switch (event.type) {
            case 'checkout.session.completed':
                const session = event.data.object;
                const userId = session.metadata.user_id;
                const tier = session.metadata.tier;
                
                console.log(`[PAYMENT] Payment successful for user ${userId} - upgrading to ${tier}`);
                
                const userService = require('./user_service');
                const success = userService.updateUserTier(userId, tier);

                if (success) {
                    console.log(`[PAYMENT] Fulfillment complete: User ${userId} is now ${tier}`);
                } else {
                    console.error(`[PAYMENT] Fulfillment FAILED: Could not update user ${userId}`);
                }

                return {
                    success: true,
                    action: 'upgrade_user',
                    user_id: userId,
                    new_tier: tier,
                    fulfillment_status: success ? 'completed' : 'failed'
                };

            case 'customer.subscription.deleted':
                const subscription = event.data.object;
                console.log(`[PAYMENT] Subscription canceled: ${subscription.id}`);
                
                // TODO: Downgrade utilisateur vers tier gratuit
                return {
                    success: true,
                    action: 'downgrade_user'
                };

            case 'invoice.payment_failed':
                const invoice = event.data.object;
                console.log(`[PAYMENT] Payment failed: ${invoice.id}`);
                
                return {
                    success: true,
                    action: 'payment_failed',
                    notify_user: true
                };

            default:
                console.log(`[PAYMENT] Unhandled event type: ${event.type}`);
                return { success: true, action: 'ignored' };
        }
    }

    /**
     * Obtenir les informations de tarification
     * @returns {Object} - Pricing public
     */
    getPricingInfo() {
        return {
            operator: {
                monthly: {
                    price: this.PRICING.operator.monthly / 100,
                    currency: 'USD',
                    features: this.PRICING.operator.features
                },
                yearly: {
                    price: this.PRICING.operator.yearly / 100,
                    currency: 'USD',
                    savings: '2 mois gratuits',
                    features: this.PRICING.operator.features
                }
            },
            enterprise: {
                monthly: {
                    price: this.PRICING.enterprise.monthly / 100,
                    currency: 'USD',
                    features: this.PRICING.enterprise.features
                },
                yearly: {
                    price: this.PRICING.enterprise.yearly / 100,
                    currency: 'USD',
                    savings: '2 mois gratuits',
                    features: this.PRICING.enterprise.features
                }
            }
        };
    }
}

module.exports = PaymentService;
