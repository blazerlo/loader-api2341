import { checkPassword } from './lib/password.js';
import { getActiveSession, destroySession } from './lib/session.js';
import { redis } from './lib/redis.js';
import { getLogs, clearLogs } from './lib/logs.js';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { password, action, key, status, code, client, hwid, oneTime } = req.body;

  if (!password || typeof password !== 'string') {
    return res.status(401).json({ error: 'Password required' });
  }

  if (!checkPassword(password)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    switch (action) {
      case 'listKeys': {
        const keys = await redis.keys('key:*');
        const result = [];
        for (const k of keys) {
          const data = await redis.get(k);
          const keyName = k.replace('key:', '');
          const session = await getActiveSession(keyName);
          result.push({
            key: keyName,
            status: data?.status || 'unlink',
            hwid: data?.hwid || null,
            oneTime: data?.oneTime || false,
            used: data?.used || false,
            sessionActive: !!session,
            sessionHwid: session?.hwid || null
          });
        }
        return res.json({ success: true, keys: result });
      }

      case 'setKey': {
        if (!key || !['link', 'unlink'].includes(status)) {
          return res.status(400).json({ error: 'Invalid key or status' });
        }
        const data = { status };
        if (hwid !== undefined) data.hwid = hwid;
        if (oneTime !== undefined) data.oneTime = oneTime;
        data.used = false;
        await redis.set(`key:${key}`, data);
        return res.json({ success: true, message: `Key ${key} set to ${status}` });
      }

      case 'deleteKey': {
        if (!key) return res.status(400).json({ error: 'Key required' });
        await destroySession(key);
        await redis.del(`key:${key}`);
        return res.json({ success: true, message: `Key ${key} deleted` });
      }

      case 'resetSession': {
        if (!key) return res.status(400).json({ error: 'Key required' });
        await destroySession(key);
        return res.json({ success: true, message: `Session for key ${key} reset` });
      }

      case 'setClient': {
        if (!client) return res.status(400).json({ error: 'Client code required' });
        await redis.set('client:code', client);
        return res.json({ success: true, message: 'Client code updated' });
      }

      case 'getClient': {
        const currentClient = await redis.get('client:code');
        return res.json({ success: true, client: currentClient });
      }

      case 'getLogs': {
        const logs = await getLogs();
        return res.json({ success: true, ...logs });
      }

      case 'clearLogs': {
        await clearLogs();
        return res.json({ success: true, message: 'Logs cleared' });
      }

      case 'setCode': {
        if (!code) return res.status(400).json({ error: 'Code required' });
        await redis.set('script:code', code);
        return res.json({ success: true, message: 'Script code updated' });
      }

      case 'getCode': {
        const currentCode = await redis.get('script:code');
        return res.json({ success: true, code: currentCode });
      }

      default:
        return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (error) {
    console.error('Admin error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
}
