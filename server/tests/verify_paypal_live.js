const paypal = require('@paypal/checkout-server-sdk');
require('dotenv').config();

// Force Live
const Environment = paypal.core.LiveEnvironment;
const client = new paypal.core.PayPalHttpClient(
    new Environment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_CLIENT_SECRET)
);

(async () => {
    console.log('Testing PayPal LIVE Environment...');
    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
        intent: 'CAPTURE',
        purchase_units: [{ amount: { currency_code: 'USD', value: '1.00' } }]
    });

    try {
        const order = await client.execute(request);
        console.log('✅ LIVE Auth Success! Order ID:', order.result.id);
        process.exit(0);
    } catch (err) {
        console.error('❌ LIVE Auth Failed:', err.message);
        if (err.statusCode === 401) {
            console.log('Credentials definitely invalid for Live.');
        }
        process.exit(1);
    }
})();
