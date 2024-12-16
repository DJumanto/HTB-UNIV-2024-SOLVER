import { createUser } from './userService.js';
import { hsetObject, rpushList } from '../utils/redisUtils.js';
import { getAllCoins } from '../services/coinService.js';
import crypto from 'crypto';

const FINANCIAL_CONTROLLER_EMAIL = 'financial-controller@frontier-board.htb';

const randomizeAmount = (baseAmount, minFluctuation = 0.9, maxFluctuation = 1.1) => {
    const multiplier = minFluctuation + Math.random() * (maxFluctuation - minFluctuation);
    return Math.floor(baseAmount * multiplier);
};

const randomizeDate = (baseDate, daysRange = 30) => {
    const date = new Date(baseDate);
    date.setDate(date.getDate() - Math.floor(Math.random() * daysRange));
    return date.toISOString();
};

export const initializeFinancialController = async () => {
    try {
        const password = crypto.randomBytes(15).toString('hex');
        await createUser(FINANCIAL_CONTROLLER_EMAIL, password);

        const walletKey = `wallet:${FINANCIAL_CONTROLLER_EMAIL}`;
        const transactionsKey = `transactions:${FINANCIAL_CONTROLLER_EMAIL}`;

        const allCoins = await getAllCoins();

        const transactions = [];

        allCoins.forEach((coin) => {
            const baseAllocationAmount =
                coin.symbol === 'CLCR'
                    ? Math.floor(coin.totalSupply * 0.51)
                    : Math.floor(coin.totalSupply * 0.43);

            const allocationAmount = randomizeAmount(baseAllocationAmount, 0.8, 1.2);

            transactions.push({
                type: 'allocation',
                coin: coin.symbol,
                amount: allocationAmount,
                timestamp: randomizeDate(new Date(), 30),
            });
        });

        for (let i = 0; i < 15; i++) {
            const randomCoin = allCoins[Math.floor(Math.random() * allCoins.length)];
            const baseTransactionAmount = Math.floor(randomCoin.totalSupply * 0.01);
            const transactionAmount = randomizeAmount(baseTransactionAmount, 0.8, 1.2);

            transactions.push({
                type: 'market-buy',
                coin: randomCoin.symbol,
                amount: transactionAmount,
                timestamp: randomizeDate(new Date(), 30),
            });
        }

        transactions.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

        const cumulativeHoldings = transactions.reduce((acc, transaction) => {
            acc[transaction.coin] = (acc[transaction.coin] || 0) + transaction.amount;
            return acc;
        }, {});

        for (const [coin, value] of Object.entries(cumulativeHoldings)) {
            await hsetObject(walletKey, { [coin]: value });
        }

        for (const transaction of transactions) {
            await rpushList(transactionsKey, JSON.stringify(transaction));
        }
    } catch (error) {
        console.error('Error initializing Financial Controller:', error.message);
    }
};
