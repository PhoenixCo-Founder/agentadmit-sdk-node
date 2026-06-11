/**
 * agentadmit/webhooks.ts
 * Verification for inbound AgentAdmit alert webhooks.
 *
 * AgentAdmit signs every alert webhook delivery with the app's webhook
 * signing secret (`whsec_…`, returned once when the webhook URL is
 * configured). The signature arrives in the `X-AgentAdmit-Signature` header:
 *
 *     X-AgentAdmit-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
 *
 * where the HMAC input is `${t}.${rawBody}` keyed with the full whsec_
 * secret. Always verify against the raw request body, before JSON parsing
 * (use `express.raw()` or capture the body with a verify hook).
 */

import { createHmac, timingSafeEqual } from 'crypto';

export const SIGNATURE_HEADER = 'X-AgentAdmit-Signature';
export const DEFAULT_TOLERANCE_SECONDS = 300;

export class WebhookSignatureError extends Error {
  constructor(message = 'Webhook signature verification failed') {
    super(message);
    this.name = 'WebhookSignatureError';
  }
}

export interface VerifyWebhookSignatureOptions {
  /**
   * Maximum allowed clock skew (seconds) between the signature timestamp and
   * now; deliveries outside the window are rejected to prevent replay.
   * Set to 0 to disable. Default: 300.
   */
  toleranceSeconds?: number;
  /** Override the current unix timestamp (for tests). */
  now?: number;
}

/**
 * Verify the X-AgentAdmit-Signature header on an inbound alert webhook.
 * Throws WebhookSignatureError on any failure; the message never includes
 * the secret or the payload.
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  signatureHeader: string,
  secret: string,
  options: VerifyWebhookSignatureOptions = {},
): void {
  const { toleranceSeconds = DEFAULT_TOLERANCE_SECONDS, now } = options;

  if (!secret) throw new WebhookSignatureError('Webhook signing secret is required');
  if (!signatureHeader) throw new WebhookSignatureError('Missing X-AgentAdmit-Signature header');

  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf-8');

  let timestamp: number | null = null;
  const candidates: string[] = [];
  for (const part of signatureHeader.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (key === 't') {
      timestamp = /^\d+$/.test(value) ? parseInt(value, 10) : null;
      if (timestamp === null) throw new WebhookSignatureError('Malformed signature header');
    } else if (key === 'v1') {
      candidates.push(value);
    }
  }

  if (timestamp === null || candidates.length === 0) {
    throw new WebhookSignatureError('Malformed signature header');
  }

  if (toleranceSeconds) {
    const current = now ?? Math.floor(Date.now() / 1000);
    if (Math.abs(current - timestamp) > toleranceSeconds) {
      throw new WebhookSignatureError('Signature timestamp outside tolerance window');
    }
  }

  const expected = createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(body)
    .digest('hex');
  const expectedBuf = Buffer.from(expected, 'utf-8');

  const matched = candidates.some(candidate => {
    const candidateBuf = Buffer.from(candidate, 'utf-8');
    return candidateBuf.length === expectedBuf.length && timingSafeEqual(candidateBuf, expectedBuf);
  });

  if (!matched) {
    throw new WebhookSignatureError('Signature verification failed');
  }
}

/** Boolean form of verifyWebhookSignature(). */
export function isValidWebhookSignature(
  payload: string | Buffer,
  signatureHeader: string,
  secret: string,
  options: VerifyWebhookSignatureOptions = {},
): boolean {
  try {
    verifyWebhookSignature(payload, signatureHeader, secret, options);
    return true;
  } catch (err) {
    if (err instanceof WebhookSignatureError) return false;
    throw err;
  }
}
