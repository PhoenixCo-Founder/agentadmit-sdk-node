/** Tests for src/webhooks.ts — X-AgentAdmit-Signature verification. */

import { createHmac } from 'crypto';
import {
  isValidWebhookSignature,
  verifyWebhookSignature,
  WebhookSignatureError,
} from '../src/webhooks';

const SECRET = 'whsec_test123';
const PAYLOAD = Buffer.from('{"event":"agentadmit.alert","alert_type":"usage_spike"}');
const NOW = 1750000000;

function sign(payload: Buffer, secret = SECRET, timestamp = NOW): string {
  const digest = createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(payload)
    .digest('hex');
  return `t=${timestamp},v1=${digest}`;
}

describe('verifyWebhookSignature', () => {
  it('accepts a valid signature', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD), SECRET, { now: NOW }),
    ).not.toThrow();
  });

  it('accepts a string payload', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD.toString(), sign(PAYLOAD), SECRET, { now: NOW }),
    ).not.toThrow();
  });

  it('rejects a tampered payload', () => {
    expect(() =>
      verifyWebhookSignature(Buffer.concat([PAYLOAD, Buffer.from(' ')]), sign(PAYLOAD), SECRET, { now: NOW }),
    ).toThrow(WebhookSignatureError);
  });

  it('rejects a signature made with the wrong secret', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD, 'whsec_other456'), SECRET, { now: NOW }),
    ).toThrow('verification failed');
  });

  it('rejects a stale timestamp', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD, SECRET, NOW - 600), SECRET, { now: NOW }),
    ).toThrow('tolerance');
  });

  it('rejects a future timestamp', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD, SECRET, NOW + 600), SECRET, { now: NOW }),
    ).toThrow('tolerance');
  });

  it('accepts a timestamp within tolerance', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD, SECRET, NOW - 200), SECRET, { now: NOW }),
    ).not.toThrow();
  });

  it('skips the timestamp check when tolerance is 0', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, sign(PAYLOAD, SECRET, NOW - 99999), SECRET, {
        toleranceSeconds: 0,
        now: NOW,
      }),
    ).not.toThrow();
  });

  it('rejects a missing header', () => {
    expect(() => verifyWebhookSignature(PAYLOAD, '', SECRET, { now: NOW })).toThrow('Missing');
  });

  it.each(['nonsense', 't=abc,v1=def', 't=123', 'v1=abc'])(
    'rejects malformed header %p',
    header => {
      expect(() => verifyWebhookSignature(PAYLOAD, header, SECRET, { now: NOW })).toThrow(
        'Malformed',
      );
    },
  );

  it('rejects a missing secret', () => {
    expect(() => verifyWebhookSignature(PAYLOAD, sign(PAYLOAD), '', { now: NOW })).toThrow(
      'secret',
    );
  });

  it('accepts when any v1 candidate matches', () => {
    expect(() =>
      verifyWebhookSignature(PAYLOAD, `${sign(PAYLOAD)},v1=deadbeef`, SECRET, { now: NOW }),
    ).not.toThrow();
  });
});

describe('isValidWebhookSignature', () => {
  it('returns booleans instead of throwing', () => {
    expect(isValidWebhookSignature(PAYLOAD, sign(PAYLOAD), SECRET, { now: NOW })).toBe(true);
    expect(
      isValidWebhookSignature(Buffer.concat([PAYLOAD, Buffer.from('x')]), sign(PAYLOAD), SECRET, {
        now: NOW,
      }),
    ).toBe(false);
  });
});
