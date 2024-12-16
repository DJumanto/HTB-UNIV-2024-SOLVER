import { hsetObject, hgetAllObject, hdelFields, existsKey, deleteKey, getKey, setKeyWithTTL } from '../utils/redisUtils.js';
import { createDefaultWallet } from './coinService.js';
import { setOtpForUser } from './otpService.js'
import bcrypt from 'bcrypt';

export const createUser = async (email, password) => {
    const hashedPassword = await bcrypt.hash(password, 10);

    const userKey = `user:${email}`;
    if (await existsKey(userKey)) {
        throw new Error(`User with email ${email} already exists`);
    }

    const userData = {
        email,
        password: hashedPassword
    };

    await hsetObject(userKey, userData);
    await createDefaultWallet(email);

    await setOtpForUser(email);
    return { email };
};

export const getUser = async (email) => {
    const userKey = `user:${email}`;
    const user = await hgetAllObject(userKey);

    if (user) {
        return {
            email: user.email,
            password: user.password
        };
    }
    return null;
};

export const validateUserExists = async (email) => {
    const userKey = `user:${email}`
    return await existsKey(userKey)
}

export const addFriendRequest = async (from, to) => {
    const friendRequestKey = `friend_requests:${to}`
    await hsetObject(friendRequestKey, { [from]: 'pending' })
    return { success: true, message: 'Friend request sent.' }
}

export const processFriendRequest = async (from, to, action) => {
    const friendRequestKey = `friend_requests:${to}`
    const friendListKey = `friends:${to}`
    const senderFriendListKey = `friends:${from}`
    const requests = (await hgetAllObject(friendRequestKey)) || {}

    if (requests[from] !== 'pending') {
        throw new Error(`No pending friend request from ${from}.`)
    }

    if (action === 'accept') {
        await hsetObject(friendListKey, { [from]: true })
        await hsetObject(senderFriendListKey, { [to]: true })
        await hdelFields(friendRequestKey, from)
        return { success: true, message: 'Friend request accepted.' }
    } else if (action === 'decline') {
        await hdelFields(friendRequestKey, from)
        return { success: true, message: 'Friend request declined.' }
    } else {
        throw new Error('Invalid action for processing friend request.')
    }
}

export const getFriendRequests = async (userId) => {
    const friendRequestKey = `friend_requests:${userId}`
    const requests = (await hgetAllObject(friendRequestKey)) || {}
    return Object.entries(requests).filter(([_, status]) => status === 'pending')
}

export const getFriends = async (userId) => {
    const friendListKey = `friends:${userId}`
    const friends = (await hgetAllObject(friendListKey)) || {}
    return Object.keys(friends)
}