import { createUser, getUser } from '../services/userService.js';
import { createToken } from '../services/jwksService.js';
import { jwksMiddleware } from '../middleware/jwksMiddleware.js';
import bcrypt from 'bcrypt';

export default async function authRoutes(fastify) {
    fastify.post('/login', async (req, reply) => {
        const { email, password } = req.body;

        try {
            const user = await getUser(email);

            if (!user) {
                return reply.status(401).send({ error: 'Invalid email or password' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return reply.status(401).send({ error: 'Invalid email or password' });
            }

            const token = await createToken({ email });

            reply.send({ token, message: 'Login successful' });
        } catch (err) {
            console.error('Error during login:', err);
            reply.status(500).send({ error: 'Internal server error' });
        }
    });

    fastify.post('/register', async (req, reply) => {
        const { email, password } = req.body;

        try {
            await createUser(email, password);

            const token = await createToken({ email });

            reply.send({ token, message: 'Registration successful' });
        } catch (err) {
            if (err.message.includes('already exists')) {
                reply.status(400).send({ error: 'User already exists' });
            } else {
                console.error('Error during registration:', err);
                reply.status(500).send({ error: 'Internal server error' });
            }
        }
    });
}