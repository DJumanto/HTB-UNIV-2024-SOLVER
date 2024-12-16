import { setHash, hgetField, deleteKey, getKeysByPattern } from '../utils/redisUtils.js';

let isRotating = false;

export const generateOtp = () => {
  return Math.floor(1000 + Math.random() * 9000).toString();
};

export const setOtpForUser = async (userId) => {
  const otp = generateOtp();
  const ttl = 60;

  await setHash(`otp:${userId}`, { otp, expiresAt: Date.now() + ttl * 1000 });

  return otp;
};

export const initializeOtps = async () => {
    const userKeys = await getKeysByPattern('user:*');

    for (const userKey of userKeys) {
        const userId = userKey.split(':')[1];
        await setOtpForUser(userId);
    }
};

export const validateOtp = async (userId, inputOtp) => {
  const otpKey = `otp:${userId}`;
  const storedOtp = await hgetField(otpKey, 'otp');

  if (!storedOtp || storedOtp !== inputOtp) {
    return false;
  }

  await deleteKey(otpKey);
  return true;
};

export const rotateOtps = async () => {
  try {
    const userKeys = await getKeysByPattern('user:*');

    const rotatePromises = userKeys.map(async (userKey) => {
      const userId = userKey.split(':')[1];
      await setOtpForUser(userId);
    });

    await Promise.all(rotatePromises);
  } catch (error) {
    console.error('Error during OTP rotation:', error);
  }
};


export const safelyRotateOtps = async () => {
  if (isRotating) {
    console.warn('Previous OTP rotation is still in progress. Skipping this interval.');
    return;
  }

  isRotating = true;
  try {
    await rotateOtps();
  } catch (error) {
    console.error('Error during OTP rotation:', error);
  } finally {
    isRotating = false;
  }
};

setInterval(safelyRotateOtps, 60000);

