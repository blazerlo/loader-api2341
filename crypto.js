import { refreshSession } from './lib/session.js';
import { hashFingerprint } from './lib/crypto.js';
import { redis } from './lib/redis.js';
import { addLog } from './lib/logs.js';

const TOKEN_TTL = 120;

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
      await addLog('heartbeat', { level: 'error', event: 'kick', reason: 'Session expired', kick: true, ip });
      return res.status(403).send('Invalid or expired session');
    }

    const fpHash = hashFingerprint(tokenData.hwid, fingerprint);
    if (tokenData.fingerprint !== fpHash) {
      await addLog('heartbeat', {
        level: 'error',
        event: 'kick',
        reason: 'Fingerprint mismatch',
        kick: true,
        key: tokenData.key,
        ip,
      });
      return res.status(403).send('Fingerprint mismatch');
    }

    const keyData = await redis.get(`key:${tokenData.key}`);
    if (!keyData || keyData.status !== 'link') {
      await addLog('heartbeat', { level: 'error', event: 'kick', reason: 'Key not found or unlinked', kick: true, key: tokenData.key, ip });
      return res.status(403).send('Key not found or unlinked');
    }

    if (keyData.used) {
      await addLog('heartbeat', { level: 'error', event: 'kick', reason: 'Key already used', kick: true, key: tokenData.key, ip });
      return res.status(403).send('Key already used');
    }

    if (keyData.hwid && keyData.hwid !== tokenData.hwid) {
      await addLog('heartbeat', { level: 'error', event: 'kick', reason: 'HWID mismatch', kick: true, key: tokenData.key, ip });
      return res.status(403).send('HWID unauthorized');
    }

    const result = await refreshSession(tokenData.key, tokenData.hwid, fpHash);
    if (!result.ok) {
      await addLog('heartbeat', { level: 'error', event: 'kick', reason: result.reason, kick: true, key: tokenData.key, ip });
      return res.status(403).send(result.reason);
    }

    await redis.set(`token:${token}`, tokenData, { ex: TOKEN_TTL });

    await addLog('heartbeat', {
      level: 'success',
      event: 'alive',
      key: tokenData.key,
      hwid: tokenData.hwid,
      ip,
    });

    return res.send('OK');
  } catch (error) {
    console.error('Heartbeat error:', error);
    await addLog('heartbeat', { level: 'error', event: 'kick', reason: 'Server error', kick: true, reason2: String(error.message || error), ip });
    return res.status(500).send('Internal server error');
  }
}
