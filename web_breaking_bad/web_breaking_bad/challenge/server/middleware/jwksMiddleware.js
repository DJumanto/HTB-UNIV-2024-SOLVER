import { verifyToken } from '../services/jwksService.js';

export const jwksMiddleware = () => {
  return async (req, reply) => {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      reply.status(401).send({ error: 'Access token is required' });
      return;
    }

    try {
      const decoded = await verifyToken(token);
      console.log("=======================");
      console.log(decoded);
      console.log("=======================");
      req.user = {
        email: decoded.email,
      };
    } catch (error) {
      console.log(error);
      reply.status(401).send({ error: 'Invalid Signature' });
    }
  };
};
