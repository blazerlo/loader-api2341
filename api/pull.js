import { xorEncrypt, hashFingerprint } from './lib/crypto.js';
import { redis } from './lib/redis.js';
import { addLog } from './lib/logs.js';

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).send('Method not allowed');
  }

  const token = req.headers['x-session-token'];
  const fingerprint = req.headers['fingerprint'];
  const ip = clientIp(req);

  if (!token) return res.status(400).send('Session token required');
  if (!fingerprint) return res.status(400).send('Fingerprint required');

  try {
    const tokenData = await redis.get(`token:${token}`);
    if (!tokenData) {
      await addLog('script', { level: 'error', event: 'pull_token_expired', ip });
      return res.status(403).send('Invalid or expired session');
    }

    const fpHash = hashFingerprint(tokenData.hwid, fingerprint);
    if (tokenData.fingerprint !== fpHash) {
      await addLog('script', { level: 'error', event: 'pull_fingerprint_mismatch', key: tokenData.key, ip });
      return res.status(403).send('Fingerprint mismatch');
    }

    const scriptCode = await redis.get('script:code');
    if (!scriptCode) {
      await addLog('script', { level: 'error', event: 'script_missing', key: tokenData.key, ip });
      return res.status(404).send('Script not found');
    }

    const encrypted = xorEncrypt(scriptCode, token);

    await addLog('script', {
      level: 'success',
      event: 'script_pulled',
      key: tokenData.key,
      hwid: tokenData.hwid,
      size: scriptCode.length,
      ip,
    });

    res.setHeader('Content-Type', 'text/plain');
    return res.send(encrypted);
  } catch (error) {
    console.error('Pull error:', error);
    await addLog('script', { level: 'error', event: 'pull_error', reason: String(error.message || error), ip });
    return res.status(500).send('Internal server error');
  }
}
