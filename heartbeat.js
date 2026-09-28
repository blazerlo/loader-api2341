import { createSession } from './lib/session.js';
import { generateToken, hashFingerprint } from './lib/crypto.js';
import { redis } from './lib/redis.js';
import { addLog } from './lib/logs.js';

const TOKEN_TTL = 120;

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (fwd) return String(fwd).split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, fingerprint');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { Key } = req.query;
  const fingerprint = req.headers['fingerprint'] || req.query.fingerprint;
  const ip = clientIp(req);

  if (!Key || typeof Key !== 'string') {
    await addLog('script', { level: 'error', event: 'gate_rejected', reason: 'Key required', ip });
    return res.status(400).json({ error: 'Key required' });
  }

  if (!fingerprint || typeof fingerprint !== 'string') {
    await addLog('script', { level: 'error', event: 'gate_rejected', reason: 'Fingerprint required', key: Key, ip });
    return res.status(400).json({ error: 'Fingerprint required' });
  }

  try {
    const data = await redis.get(`key:${Key}`);

    if (!data) {
      await addLog('script', { level: 'error', event: 'key_not_found', key: Key, fp: fingerprint, ip });
      return res.status(403).json({ error: 'Invalid or unlinked key' });
    }

    if (data.status !== 'link') {
      await addLog('script', { level: 'error', event: 'key_unlinked', key: Key, ip });
      return res.status(403).json({ error: 'Invalid or unlinked key' });
    }

    if (data.used === true) {
      await addLog('script', { level: 'error', event: 'key_already_used', key: Key, ip });
      return res.status(403).json({ error: 'Key already used' });
    }

    const hwid = data.hwid || fingerprint;
    const fpHash = hashFingerprint(hwid, fingerprint);

    if (data.fingerprint && data.fingerprint !== fpHash) {
      await addLog('script', { level: 'error', event: 'fingerprint_mismatch', key: Key, ip });
      return res.status(403).json({ error: 'Fingerprint mismatch' });
    }

    const sessionResult = await createSession(Key, hwid, fpHash);
    if (!sessionResult.ok) {
      await addLog('script', { level: 'error', event: 'session_denied', key: Key, reason: sessionResult.reason, ip });
      return res.status(403).json({ error: sessionResult.reason });
    }

    if (!data.hwid) {
      data.hwid = hwid;
      data.fingerprint = fpHash;
      await redis.set(`key:${Key}`, data);
      await addLog('script', { level: 'info', event: 'hwid_bound', key: Key, hwid, ip });
    }

    const sessionToken = generateToken();
    await redis.set(`token:${sessionToken}`, { key: Key, hwid, fingerprint: fpHash }, { ex: TOKEN_TTL });

    await addLog('script', {
      level: 'success',
      event: sessionResult.resumed ? 'session_resumed' : 'session_created',
      key: Key,
      hwid,
      ip,
    });

    return res.json({
      Session_Token: sessionToken,
      Token_Echo: sessionToken.substring(0, 16),
    });
  } catch (error) {
    console.error('Gate error:', error);
    await addLog('script', { level: 'error', event: 'gate_error', key: Key, reason: String(error.message || error), ip });
    return res.status(500).json({ error: 'Internal server error' });
  }
}
