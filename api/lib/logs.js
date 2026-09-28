import { redis } from './redis.js';

const SCRIPT_LOG = 'logs:script';
const HEARTBEAT_LOG = 'logs:heartbeat';
const MAX_ENTRIES = 100;

export async function addLog(bucket, entry) {
  const key = bucket === 'heartbeat' ? HEARTBEAT_LOG : SCRIPT_LOG;
  const payload = JSON.stringify({ t: Date.now(), ...entry });
  await redis.lpush(key, payload);
  await redis.ltrim(key, 0, MAX_ENTRIES - 1);
}

export function parseLog(raw) {
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return { t: 0, level: 'error', msg: String(raw) };
    }
  }
  return raw;
}

export async function getLogs() {
  const [scriptRaw, hbRaw] = await Promise.all([
    redis.lrange(SCRIPT_LOG, 0, MAX_ENTRIES - 1),
    redis.lrange(HEARTBEAT_LOG, 0, MAX_ENTRIES - 1),
  ]);
  return {
    script: (scriptRaw || []).map(parseLog),
    heartbeat: (hbRaw || []).map(parseLog),
  };
}

export async function clearLogs() {
  await redis.del(SCRIPT_LOG, HEARTBEAT_LOG);
}
