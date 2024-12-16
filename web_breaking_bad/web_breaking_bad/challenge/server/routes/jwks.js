import { getJWKS } from '../services/jwksService.js';

export default async function jwksRouter(fastify) {
    fastify.get('/jwks.json', async (req, reply) => {
        try {
            const jwks = await getJWKS();
            return reply.send(jwks);
        } catch (err) {
            fastify.log.error(err);
            return reply.status(500).send({ error: 'Could not retrieve JWKS' });
        }
    });
}