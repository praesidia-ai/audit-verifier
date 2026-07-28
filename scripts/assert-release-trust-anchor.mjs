import crypto from 'node:crypto';
import {
  PLATFORM_PUBLIC_KEY_DER_B64,
  PLATFORM_PUBLIC_KEY_FINGERPRINT,
} from '../dist/platform-pubkey.js';

function fail(message) {
  process.stderr.write(`audit-verifier release blocked: ${message}\n`);
  process.exitCode = 1;
}

if (!PLATFORM_PUBLIC_KEY_DER_B64 || !PLATFORM_PUBLIC_KEY_FINGERPRINT) {
  fail(
    'the embedded platform trust anchor is empty; pin the production public key before publishing',
  );
} else {
  try {
    const der = Buffer.from(PLATFORM_PUBLIC_KEY_DER_B64, 'base64');
    if (der.toString('base64') !== PLATFORM_PUBLIC_KEY_DER_B64) {
      fail('PLATFORM_PUBLIC_KEY_DER_B64 is not canonical base64');
    } else {
      const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
      if (key.asymmetricKeyType !== 'ec') {
        fail('the embedded trust anchor is not an EC public key');
      } else {
        const fingerprint = crypto.createHash('sha256').update(der).digest('hex');
        if (fingerprint !== PLATFORM_PUBLIC_KEY_FINGERPRINT.toLowerCase()) {
          fail('the embedded key does not match PLATFORM_PUBLIC_KEY_FINGERPRINT');
        }
      }
    }
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
