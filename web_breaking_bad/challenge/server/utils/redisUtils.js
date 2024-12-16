import redisClient from './redisClient.js';

export const setKey = async (key, value) => {
    await redisClient.set(key, value);
};

export const setKeyWithTTL = async (key, value, ttl = 3600) => {
    if (ttl > 0) {
        await redisClient.set(key, value, 'EX', ttl);
    } else {
        await redisClient.set(key, value);
    }
};

export const getKey = async (key) => {
    return await redisClient.get(key);
};

export const getKeysByPattern = async (pattern) => {
    return await redisClient.keys(pattern);
};

export const getHash = async (key) => {
    const data = await redisClient.hgetall(key);
    if (!data || Object.keys(data).length === 0) return null;

    const parsedData = {};
    for (const [field, value] of Object.entries(data)) {
        try {
            parsedData[field] = JSON.parse(value);
        } catch {
            parsedData[field] = value;
        }
    }
    return parsedData;
};

export const getListRange = async (key, start = 0, end = -1) => {
    return await redisClient.lrange(key, start, end);
};

export const existsKey = async (key) => {
    return await redisClient.exists(key) === 1;
};

export const expireKey = async (key, ttl) => {
    await redisClient.expire(key, ttl);
};

export const hsetObject = async (key, obj) => {
    const flattened = Object.entries(obj).flat();
    await redisClient.hset(key, flattened);
};

export const hgetAllObject = async (key) => {
    const data = await redisClient.hgetall(key);
    if (!data || Object.keys(data).length === 0) return null;

    return Object.entries(data).reduce((obj, [field, value]) => {
        try {
            obj[field] = JSON.parse(value);
        } catch {
            obj[field] = value;
        }
        return obj;
    }, {});
};

export const pushToList = async (key, value) => {
    await redisClient.rpush(key, value);
};

export const lrangeList = async (key, start, stop) => {
    return redisClient.lrange(key, start, stop);
};

export const setHash = async (key, obj) => {
    const flattened = Object.entries(obj).flat();
    await redisClient.hset(key, flattened);
};

export const hsetField = async (key, field, value) => {
    await redisClient.hset(key, field, value);
};

export const hgetField = async (key, field) => {
    return await redisClient.hget(key, field);
};

export const hincrby = async (key, field, increment) => {
    return await redisClient.hincrby(key, field, increment);
};

export const hexistsField = async (key, field) => {
    return await redisClient.hexists(key, field);
};

export const hdelFields = async (key, ...fields) => {
    return await redisClient.hdel(key, ...fields);
};

export const rpushList = async (key, value) => {
    await redisClient.rpush(key, value);
};

export const lpopList = async (key) => {
    return await redisClient.lpop(key);
};

export const getList = async (key) => {
    return await redisClient.lrange(key, 0, -1);
};

export const getHashKey = async (key, field) => {
    return await redisClient.hget(key, field);
};

export const getListLength = async (key) => {
    return await redisClient.llen(key);
};

export const deleteKey = async (key) => {
    return await redisClient.del(key);
};

export const hincrbyfloat = async (key, field, increment) => {
    return await redisClient.hincrbyfloat(key, field, increment);
};
