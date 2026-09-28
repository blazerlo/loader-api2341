import { Redis } from '@upstash/redis';

const url = process.env.OUTLAW_REDIS_URL;
const token = process.env.OUTLAW_REDIS_TOKEN;

if (!url || !token) {
  throw new Error('OUTLAW_REDIS_URL / OUTLAW_REDIS_TOKEN not configured');
}

export const redis = new Redis({ url, token });
