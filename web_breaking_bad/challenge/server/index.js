import Fastify from 'fastify';
import { CronJob } from 'cron';

import { generateKeys } from './services/jwksService.js';
import { initializeFinancialController } from './services/initializer.js';
import { initializeCoins } from './services/coinService.js';
import { jwksMiddleware } from './middleware/jwksMiddleware.js';
import authRoutes from './routes/auth.js';
import cryptoRoutes from './routes/crypto.js';
import dashboardRouter from './routes/dashboard.js';
import jwksRouter from './routes/jwks.js';
import usersRouter from './routes/users.js';
import analyticsRoutes from './routes/analytics.js';
import { safelyRotateOtps } from './services/otpService.js';

const fastify = Fastify();

fastify.register(analyticsRoutes, { prefix: '/api/analytics' });
fastify.register(authRoutes, { prefix: '/api/auth' });
fastify.register(jwksRouter, { prefix: '/.well-known' });

fastify.register(async (securedRoutes) => {
  securedRoutes.addHook('preHandler', jwksMiddleware());
  securedRoutes.register(usersRouter, { prefix: '/api/users' });
  securedRoutes.register(dashboardRouter, { prefix: '/api/dashboard' });
  securedRoutes.register(cryptoRoutes, { prefix: '/api/crypto' });
});

const job = new CronJob(
	'*/1 * * * *',
	safelyRotateOtps,
	null,
	false,
	'America/Los_Angeles'
);

const start = async () => {
  try {
    await generateKeys();
    await initializeCoins();
    await initializeFinancialController();

    await fastify.listen({ port: 3000, host: '0.0.0.0' });
    console.log('Server started successfully.');
    job.start()
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};


start();