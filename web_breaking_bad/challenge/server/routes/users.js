import { validateUserExists, addFriendRequest, processFriendRequest, getFriendRequests, getFriends } from '../services/userService.js';
import { rateLimiterMiddleware } from '../middleware/rateLimiterMiddleware.js';

const checkExistingFriendRequest = async (from, to) => {
    const requests = await getFriendRequests(to);
    return requests.some((req) => req[0] === from && req[1] === 'pending');
};

export default async function usersRouter(fastify) {
    fastify.post('/:action(friend-request|accept-friend|decline-friend|cancel-friend-request)', {
        preHandler: [rateLimiterMiddleware()]
    }, async (req, reply) => {
        const { action } = req.params;
        const { to, from } = req.body || {};
        const userId = req.user.email;

        if (!to && action === 'friend-request') {
            return reply.status(400).send({  error: 'Recipient user ID is required.' });
        }

        if (!from && ['accept-friend', 'decline-friend'].includes(action)) {
            return reply.status(400).send({ error: 'Sender user ID is required.' });
        }

        try {
            if (['friend-request', 'cancel-friend-request'].includes(action)) {
                const userExists = await validateUserExists(to);
                if (!userExists) {
                    return reply.status(404).send({ error: 'Recipient user does not exist.' });
                }
            }

            switch (action) {
                case 'friend-request': {
                    if (userId === to) {
                        return reply.send({ success: false, message: 'Cannot add yourself as a friend.' });
                    }

                    const existingRequest = await checkExistingFriendRequest(userId, to);
                    if (existingRequest) {
                        return reply.send({ success: false, message: 'Friend request already sent.' });
                    }

                    await addFriendRequest(userId, to);
                    reply.send({ success: true, message: 'Friend request sent successfully.' });
                    break;
                }

                case 'accept-friend': {
                    const pendingRequest = await checkExistingFriendRequest(from, userId);
                    if (!pendingRequest) {
                        return reply.send({ success: false, message: 'No pending friend request from this user.' });
                    }

                    await processFriendRequest(from, userId, 'accept');
                    reply.send({ success: true, message: 'Friend request accepted successfully.' });
                    break;
                }

                case 'decline-friend': {
                    const pendingRequest = await checkExistingFriendRequest(from, userId);
                    if (!pendingRequest) {
                        return reply.send({ success: false,  message: 'No pending friend request from this user.' });
                    }

                    await processFriendRequest(from, userId, 'decline');
                    reply.send({ success: true, message: 'Friend request declined.' });
                    break;
                }

                case 'cancel-friend-request': {
                    const pendingRequest = await checkExistingFriendRequest(userId, to);
                    if (!pendingRequest) {
                        return reply.send({ success: false, message: 'No pending friend request to cancel.' });
                    }

                    await processFriendRequest(userId, to, 'cancel');
                    reply.send({ success: true, message: 'Friend request canceled successfully.' });
                    break;
                }

                default:
                    reply.status(400).send({ error: 'Invalid action specified.' });
            }
        } catch (error) {
            reply.status(500).send({ error: `Failed to process ${action}.` });
        }
    });

    fastify.get('/friend-requests', { preHandler: [rateLimiterMiddleware()]}, async (req, reply) => {
        const userId = req.user.email;

        try {
            const requests = await getFriendRequests(userId);
            reply.send({requests});
        } catch (error) {
            reply.status(500).send({ error: 'Failed to fetch friend requests.' });
        }
    });

    fastify.get('/friends', { preHandler: [rateLimiterMiddleware()] }, async (req, reply) => {
        const userId = req.user.email;

        try {
            const friends = await getFriends(userId);
            reply.send({friends});
        } catch (error) {
            reply.status(500).send({ error: 'Failed to fetch friends.' });
        }
    });
}