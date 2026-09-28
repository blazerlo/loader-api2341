import { createHash, randomBytes } from 'crypto';

export function generateToken() {
  return randomBytes(32).toString('hex');
}

export function xorEncrypt(plainText, key) {
  const keyBytes = Buffer.from(key, 'utf-8');
  const textBytes = Buffer.from(plainText, 'utf-8');
  const result = Buffer.alloc(textBytes.length);

  for (let i = 0; i < textBytes.length; i++) {
    result[i] = textBytes[i] ^ keyBytes[i % keyBytes.length];
  }

  return result.toString('hex');
}

export function xorDecrypt(hexData, key) {
  const keyBytes = Buffer.from(key, 'utf-8');
  const dataBytes = Buffer.from(hexData, 'hex');
  const result = Buffer.alloc(dataBytes.length);

  for (let i = 0; i < dataBytes.length; i++) {
    result[i] = dataBytes[i] ^ keyBytes[i % keyBytes.length];
  }

  return result.toString('utf-8');
}

export function hashFingerprint(hwid, fingerprint) {
  return createHash('sha256')
    .update(hwid + ':' + fingerprint)
    .digest('hex')
    .substring(0, 32);
}
