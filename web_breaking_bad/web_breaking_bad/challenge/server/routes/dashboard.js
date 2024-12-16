import { checkFinancialControllerDrained } from '../services/flagService.js';

export default async function dashboardRouter(fastify) {
    fastify.get('/', async (req, reply) => {
        if (!req.user) {
            reply.status(401).send({ error: 'Unauthorized: User not authenticated' });
            return;
        }

        const { email } = req.user;

        if (!email) {
            reply.status(400).send({ error: 'Email not found in token' });
            return;
        }

        const { drained, flag } = await checkFinancialControllerDrained();

        if (drained) {
            reply.send({ message: 'Welcome to the Dashboard!', flag });
            return;
        }

        reply.send({ message: 'Welcome to the Dashboard!' });
    });
}
