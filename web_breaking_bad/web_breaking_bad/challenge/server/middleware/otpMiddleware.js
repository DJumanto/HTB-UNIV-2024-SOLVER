import { hgetField } from '../utils/redisUtils.js';

export const otpMiddleware = () => {
  return async (req, reply) => {
    const userId = req.user.email;
    const { otp } = req.body;

    const redisKey = `otp:${userId}`;
    const validOtp = await hgetField(redisKey, 'otp');

    if (!otp) {
      reply.status(401).send({ error: 'OTP is missing.' });
      return
    }

    if (!validOtp) {
      reply.status(401).send({ error: 'OTP expired or invalid.' });
      return;
    }

    // TODO: Is this secure enough?
    if (!otp.includes(validOtp)) {
      reply.status(401).send({ error: 'Invalid OTP.' });
      return;
    }
  };
};
