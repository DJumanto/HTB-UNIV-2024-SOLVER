import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';
import { setKeyWithTTL, getKey } from '../utils/redisUtils.js';

const KEY_PREFIX = 'rsa-keys';
const JWKS_URI = 'http://127.0.0.1:1337/.well-known/jwks.json';
const KEY_ID = uuidv4();

export const generateKeys = async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const publicKeyObject = crypto.createPublicKey(publicKey);
    const publicJwk = publicKeyObject.export({ format: 'jwk' });

    const jwk = {
        kty: 'RSA',
        ...publicJwk,
        alg: 'RS256',
        use: 'sig',
        kid: KEY_ID,
    };

    const jwks = {
        keys: [jwk],
    };

    await setKeyWithTTL(`${KEY_PREFIX}:private`, privateKey, 0);
    await setKeyWithTTL(`${KEY_PREFIX}:jwks`, JSON.stringify(jwks), 0);
};

const getPrivateKey = async () => {
    const privateKey = await getKey(`${KEY_PREFIX}:private`);
    if (!privateKey) {
        throw new Error('Private key not found in Redis. Generate keys first.');
    }
    return privateKey;
};

export const getJWKS = async () => {
    const jwks = await getKey(`${KEY_PREFIX}:jwks`);
    if (!jwks) {
        throw new Error('JWKS not found in Redis. Generate keys first.');
    }
    return JSON.parse(jwks);
};

export const createToken = async (payload) => {
    const privateKey = await getPrivateKey();
    return jwt.sign(payload, privateKey, {
        algorithm: 'RS256',
        header: {
            kid: KEY_ID,
            jku: JWKS_URI,
        },
    });
};

export const verifyToken = async (token) => {
    try {
        const decodedHeader = jwt.decode(token, { complete: true });

        if (!decodedHeader || !decodedHeader.header) {
            throw new Error('Invalid token: Missing header');
        }

        const { kid, jku } = decodedHeader.header;
        console.log("KID IN HEADER");
        console.log("==================================================");
        console.log(kid);
        console.log("==================================================");
        console.log(jku);
        console.log("==================================================");

        if (!jku) {
            throw new Error('Invalid token: Missing header jku');
        }

        // TODO: is this secure enough?
        if (!jku.startsWith('http://127.0.0.1:1337/')) {
            throw new Error('Invalid token: jku claim does not start with http://127.0.0.1:1337/');
        }

        if (!kid) {
            throw new Error('Invalid token: Missing header kid');
        }

        if (kid !== KEY_ID) {
            return new Error('Invalid token: kid does not match the expected key ID');
        }

        let jwks;
        try {
            const response = await axios.get(jku);
            if (response.status !== 200) {
                throw new Error(`Failed to fetch JWKS: HTTP ${response.status}`);
            }
            jwks = response.data;
        } catch (error) {
            throw new Error(`Error fetching JWKS from jku: ${error.message}`);
        }

        if (!jwks || !Array.isArray(jwks.keys)) {
            throw new Error('Invalid JWKS: Expected keys array');
        }
        const jwk = jwks.keys.find((key) => key.kid === kid);
        console.log("KID");
        console.log("==================================================");
        console.log(jwks.keys.find((key) => key.kid === kid));
        console.log("==================================================");
        if (!jwk) {
            throw new Error('Invalid token: kid not found in JWKS');
        }

        if (jwk.alg !== 'RS256') {
            throw new Error('Invalid key algorithm: Expected RS256');
        }

        if (!jwk.n || !jwk.e) {
            throw new Error('Invalid JWK: Missing modulus (n) or exponent (e)');
        }

        const publicKey = jwkToPem(jwk);

        const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
        return decoded;
    } catch (error) {
        console.error(`Token verification failed: ${error.message}`);
        throw error;
    }
};

const jwkToPem = (jwk) => {
    if (jwk.kty !== 'RSA') {
        throw new Error("Invalid JWK: Key type must be 'RSA'");
    }

    const key = {
        kty: jwk.kty,
        n: jwk.n.toString('base64url'),
        e: jwk.e.toString('base64url'),
    };

    const pem = crypto.createPublicKey({
        key,
        format: 'jwk',
    });

    return pem.export({ type: 'spki', format: 'pem' });
};