import { hsetField, hgetField, expireKey } from '../utils/redisUtils.js';

export const rateLimiterMiddleware = (limit = 5, windowInSeconds = 60) => {
  return async (req, reply) => {
    const userId = req.user.email;
    const redisKey = `rate-limit:${userId}`;

    let currentCount = await hgetField(redisKey, 'count');
    if (!currentCount) {
      currentCount = 1;
      await hsetField(redisKey, 'count', currentCount);
      await expireKey(redisKey, windowInSeconds);
    } else {
      currentCount = parseInt(currentCount, 10) + 1;
      await hsetField(redisKey, 'count', currentCount);
    }

    if (currentCount > limit) {
      reply.status(429).send({ error: 'Too many requests. Please try again later.' });
      return;
    }
  };
};
