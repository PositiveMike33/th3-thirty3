require('dotenv').config();
const FinanceService = require('./finance_service');

async function test() {
    console.log("Testing FinanceService...");
    const finance = new FinanceService();

    console.log("Fetching Portfolio...");
    const portfolio = await finance.getPortfolioData();
    console.log("Portfolio Data:", JSON.stringify(portfolio, null, 2));

    console.log("Fetching Ticker BTC/CAD...");
    const ticker = await finance.getTickerData('BTC/CAD');
    console.log("Ticker Data:", JSON.stringify(ticker, null, 2));
}

test();
