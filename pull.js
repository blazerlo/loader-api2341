import { redis } from './redis.js';

const SESSION_TTL = 60;

export async function getActiveSession(key) {
  const data = await redis.get(`session:${key}`);
  if (!data) return null;
  return data;
}

export async function isSessionActive(key) {
  const session = await getActiveSession(key);
  return !!session;
}

export async function createSession(key, hwid, fingerprint) {
  const existing = await getActiveSession(key);
  if (existing) {
    if (existing.hwid !== hwid || (fingerprint && existing.fingerprint !== fingerprint)) {
      return { ok: false, reason: 'Key is active on another device' };
    }
    await redis.expire(`session:${key}`, SESSION_TTL);
    return { ok: true, resumed: true };
  }

  const fpKey = `fingerprint:${fingerprint}`;
  const boundByFp = await redis.get(fpKey);
  if (boundByFp && boundByFp !== key) {
    return { ok: false, reason: 'Device fingerprint bound to another key' };
  }

  const hwidKey = `hwid:${hwid}`;
  const boundByHwid = await redis.get(hwidKey);
  if (boundByHwid && boundByHwid !== key) {
    return { ok: false, reason: 'HWID is bound to another key' };
  }

  await redis.set(`session:${key}`, { hwid, fingerprint, startedAt: Date.now() }, { ex: SESSION_TTL });
  await redis.set(hwidKey, key, { ex: SESSION_TTL });
  if (fingerprint) {
    await redis.set(fpKey, key, { ex: SESSION_TTL });
  }
  return { ok: true, resumed: false };
}

export async function refreshSession(key, hwid, fingerprint) {
  const session = await getActiveSession(key);
  if (!session) return { ok: false, reason: 'No active session' };
  if (session.hwid !== hwid) return { ok: false, reason: 'HWID mismatch' };
  if (fingerprint && session.fingerprint && session.fingerprint !== fingerprint) {
    return { ok: false, reason: 'Fingerprint mismatch' };
  }

  await redis.expire(`session:${key}`, SESSION_TTL);
  await redis.expire(`hwid:${hwid}`, SESSION_TTL);
  if (session.fingerprint) {
    await redis.expire(`fingerprint:${session.fingerprint}`, SESSION_TTL);
  }
  return { ok: true };
}

export async function destroySession(key) {
  const session = await getActiveSession(key);
  if (session) {
    await redis.del(`hwid:${session.hwid}`);
    if (session.fingerprint) {
      await redis.del(`fingerprint:${session.fingerprint}`);
    }
  }
  await redis.del(`session:${key}`);
  return true;
}
