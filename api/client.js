import { redis } from './lib/redis.js';
import { addLog } from './lib/logs.js';

function deny(res, status, detail) {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(status).json({ detail });
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return deny(res, 405, 'Method Not Allowed');
  }

  const Key = req.query.Key;

  if (!Key || typeof Key !== 'string') {
    return deny(res, 403, 'Forbidden');
  }

  try {
    const keyData = await redis.get(`key:${Key}`);

    if (!keyData || keyData.status !== 'link' || keyData.used) {
      await addLog('script', { level: 'error', event: 'client_denied', key: Key, reason: 'Forbidden' });
      return deny(res, 403, 'Forbidden');
    }

    const clientCode = await redis.get('client:code');
    if (!clientCode) {
      return deny(res, 404, 'Not Found');
    }

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, private');
    return res.send(clientCode);
  } catch (error) {
    console.error('Client error:', error);
    return deny(res, 500, 'Internal Server Error');
  }
}
