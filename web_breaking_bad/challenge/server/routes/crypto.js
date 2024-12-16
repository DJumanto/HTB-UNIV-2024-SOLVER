import { getAllCoins, getBalancesForUser, getCoinBySymbol, getWalletAndMarketShare, getCoinHistory, getSupportedCoins } from '../services/coinService.js';
import { getTransactions, transactionByEmail } from '../services/transactionService.js'
import { otpMiddleware } from '../middleware/otpMiddleware.js';
import { rateLimiterMiddleware } from '../middleware/rateLimiterMiddleware.js';
import { validateUserExists } from '../services/userService.js';

export default async function cryptoRoutes(fastify) {
    fastify.get('/', async (req, reply) => {
        try {
            const userId = req.user.email;
            const coins = await getAllCoins(userId);
            reply.send(coins);
        } catch (error) {
            console.error('Error fetching coins:', error);
            reply.status(500).send({ error: 'Failed to fetch coins' });
        }
    });

    fastify.get('/balance', async (req, reply) => {
        const userId = req.user.email;
    
        try {
          const balances = await getBalancesForUser(userId);
          reply.send(balances);
        } catch (error) {
          console.error('Error fetching user balances:', error);
          reply.status(500).send({ error: 'Failed to fetch user balances' });
        }
      });

    fastify.get('/market-share', async (req, reply) => {
        try {
            const marketShare = await getWalletAndMarketShare(req.user.email);
            reply.send(marketShare);
        } catch (error) {
            console.error('Error fetching market share:', error);
            reply.status(500).send({ error: 'Failed to fetch market share' });
        }
    });

    fastify.get('/:symbol/history', async (req, reply) => {
        const { symbol } = req.params;
        const { period = 24 } = req.query;

        try {
            const history = await getCoinHistory(symbol, period);
            if (!history) {
                return reply.status(404).send({ error: 'Coin not found or history unavailable' });
            }
            reply.send(history);
        } catch (error) {
            console.error('Error fetching coin history:', error);
            reply.status(500).send({ error: 'Failed to fetch coin history' });
        }
    });

    fastify.get('/:symbol', async (req, reply) => {
        const { symbol } = req.params;

        try {
            const coin = await getCoinBySymbol(symbol);
            if (!coin) {
                return reply.status(404).send({ error: 'Coin not found' });
            }
            reply.send(coin);
        } catch (error) {
            console.error('Error fetching coin by symbol:', error);
            reply.status(500).send({ error: 'Failed to fetch coin' });
        }
    });

    fastify.get('/transactions', async (req, reply) => {
        try {
            const transactions = await getTransactions(req.user.email);
            reply.send(transactions);
        } catch (error) {
            console.error('Error fetching transactions:', error);
            reply.status(500).send({ error: 'Failed to fetch transactions' });
        }
    });

    fastify.post(
        '/transaction',
        { preHandler: [rateLimiterMiddleware(), otpMiddleware()] },
        async (req, reply) => {
          const { to, coin, amount } = req.body;
          const userId = req.user.email; 
      
          try {
            if (!to || !coin || !amount) {
              return reply.status(400).send({ error: "Missing required fields" });
            }
            
            const supportedCoins = await getSupportedCoins(); 
            if (!supportedCoins.includes(coin.toUpperCase())) {
                return reply.status(400).send({ error: "Unsupported coin symbol." });
            }
            
            const parsedAmount = parseFloat(amount);
            if (isNaN(parsedAmount) || parsedAmount <= 0) {
              return reply.status(400).send({ error: "Amount must be a positive number." });
            }

            const userExists = await validateUserExists(to);
            if (!userExists) {
              return reply.status(404).send({ error: "Recipient user does not exist." });
            }
      
            if (userId === to) {
              return reply.status(400).send({ error: "Cannot perform transactions to yourself." });
            }

            const result = await transactionByEmail(to, userId, parseFloat(amount), coin.toUpperCase());
      
            if (!result.success) {
              return reply.status(result.status).send({ error: result.error });
            }
      
            reply.send(result);
          } catch (err) {
            console.error("Transaction error:", err);
            reply.status(err.status || 500).send({ error: err.error || "An unknown error occurred during the transaction." });
          }
        }
      );
}
