import { trackClick, getAnalyticsData } from '../services/analyticsService.js';

export default async function analyticsRoutes(fastify) {
    fastify.get('/redirect', async (req, reply) => {
        const { url, ref } = req.query;

        if (!url || !ref) {
            return reply.status(400).send({ error: 'Missing URL or ref parameter' });
        }
        // TODO: Should we restrict the URLs we redirect users to?
        try {
            await trackClick(ref, decodeURIComponent(url));
            reply.header('Location', decodeURIComponent(url)).status(302).send();
        } catch (error) {
            console.error('[Analytics] Error during redirect:', error.message);
            reply.status(500).send({ error: 'Failed to track analytics data.' });
        }
    });

    fastify.get('/data', async (req, reply) => {
        const { start = 0, limit = 10 } = req.query;

        try {
            const analyticsData = await getAnalyticsData(parseInt(start), parseInt(limit));
            reply.send(analyticsData);
        } catch (error) {
            console.error('[Analytics] Error fetching data:', error.message);
            reply.status(500).send({ error: 'Failed to fetch analytics data.' });
        }
    });
}
