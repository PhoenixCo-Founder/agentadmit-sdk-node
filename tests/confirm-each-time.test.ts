/**
 * Confirm-each-time (1.11.0): the hosted service refuses a designated scope
 * with `confirmation_required` and stages a ceremony for the exact action.
 * The SDK must (1) pass the confirmation block through to the agent as a
 * typed 403, (2) forward the agent's attestation header on the retry,
 * (3) compute the request digest and carry the app's action summary, and
 * (4) keep failing closed on every other refusal class.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import {
  validateAgentToken,
  requestTelemetry,
  requestDigest,
  parseActionConfirmation,
  parseActionDecline,
  ACTION_ATTESTATION_HEADER,
} from '../src/auth';
import { ConfirmationRequiredError, ConfirmationDeclinedError, VerifyRefusedError } from '../src/errors';
import { getScopeMetadata } from '../src/config';
import { createAgentAdmitRouter } from '../src/routes';
import express from 'express';
import type { Server } from 'http';
import type { AddressInfo } from 'net';

// Captured before any test swaps global.fetch, so the route test can hit a real local server.
const realFetch = global.fetch;

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-confirm-test-'));
  const cfgPath = join(dir, 'agentadmit.yaml');
  writeFileSync(cfgPath, [
    'app_id: app_test',
    'app_name: Test App',
    'api_key: aa_test_dummy',
    'agentadmit_api_url: https://api.agentadmit.test',
    'agentadmit_verify_url: https://api.agentadmit.test/api/v1/verify',
    'api_base_url: http://localhost',
    'max_retries: 0',
    'storage:',
    '  backend: memory',
    'scopes:',
    '  - name: write:payments',
    '    description: Move money',
    '    category: Payments',
    '    role: user',
    '    confirm_each_time: true',
    '  - name: read:workouts',
    '    description: Read workouts',
    '    category: Workouts',
    '    role: user',
  ].join('\n'));
  return cfgPath;
}

const CONFIRMATION = {
  action_session_id: 'asess_abc',
  action_session_url: 'https://agentadmit.com/confirm/action/asess_abc',
  expires_at: '2026-09-02T18:30:00.000Z',
  scope: 'write:payments',
  method: 'POST',
  endpoint: '/api/payments',
  request_digest: 'sha256:deadbeef',
  summary: 'Pay Alex $50',
};

function mockFetch(body: any) {
  // A fresh Response per call: a body can only be consumed once.
  const fn = jest.fn().mockImplementation(() => Promise.resolve(
    new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
  ));
  global.fetch = fn as any;
  return fn;
}

function fakeReq(overrides: Record<string, any> = {}): any {
  return { path: '/api/payments', method: 'post', headers: {}, body: { trainer: 'alex', amount: 50 }, ...overrides };
}

beforeAll(() => { loadConfig(writeTestConfig()); });

describe('confirmation_required refusal', () => {
  it('throws a typed ConfirmationRequiredError carrying the staged ceremony', async () => {
    mockFetch({
      active: true,
      error: 'confirmation_required',
      error_description: 'Scope "write:payments" requires a fresh human confirmation for each call.',
      confirmation: CONFIRMATION,
      renewal: 'The human confirms on the hosted page with their passkey.',
    });
    await expect(validateAgentToken('ag_at_x', { scope_used: 'write:payments' })).rejects.toBeInstanceOf(ConfirmationRequiredError);
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
    } catch (err: any) {
      expect(err).toBeInstanceOf(VerifyRefusedError);
      expect(err.code).toBe('confirmation_required');
      expect(err.confirmation).toEqual(CONFIRMATION);
      expect(err.payload.confirmation).toEqual(CONFIRMATION);
      expect(err.payload.renewal).toContain('passkey');
      expect(err.attestationStatus).toBeNull();
    }
  });

  it('surfaces why a presented attestation was rejected', async () => {
    mockFetch({
      active: true,
      error: 'confirmation_required',
      confirmation: CONFIRMATION,
      attestation_status: 'action_mismatch',
      attestation_description: 'That confirmation was for a different action.',
    });
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments', action_attestation_id: 'asess_old' });
      throw new Error('expected refusal');
    } catch (err: any) {
      expect(err.attestationStatus).toBe('action_mismatch');
      expect(err.payload.attestation_description).toContain('different action');
    }
  });

  it('never passes an unknown or malformed confirmation block through', async () => {
    mockFetch({ active: true, error: 'confirmation_required', confirmation: { action_session_url: 42 } });
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
      throw new Error('expected refusal');
    } catch (err: any) {
      expect(err).toBeInstanceOf(VerifyRefusedError);
      expect(err).not.toBeInstanceOf(ConfirmationRequiredError);
      expect(err.payload.confirmation).toBeUndefined();
    }
  });

  it('still fails closed on the policy-unavailable refusal', async () => {
    mockFetch({ active: true, error: 'confirmation_policy_unavailable' });
    await expect(validateAgentToken('ag_at_x', { scope_used: 'write:payments' })).rejects.toBeInstanceOf(VerifyRefusedError);
  });
});

const DECLINED = {
  action_session_id: 'asess_abc',
  declined_at: '2026-09-22T21:35:42.000Z',
  hold_until: '2026-09-22T21:50:42.000Z',
  scope: 'write:payments',
  method: 'POST',
  endpoint: '/api/payments',
  request_digest: 'sha256:deadbeef',
  summary: 'Pay Alex $50',
};

describe('confirmation_declined refusal (1.12.0)', () => {
  it('throws a typed ConfirmationDeclinedError carrying the declined block and hold', async () => {
    mockFetch({
      active: true,
      error: 'confirmation_declined',
      error_description: 'The user declined this action on the hosted confirmation page. Do not retry it unless the user asks you to; no new confirmation can be staged for this action until 2026-09-22T21:50:42.000Z.',
      declined: DECLINED,
      renewal: 'Only the user can lift a decline. After the hold ends, a retry stages a fresh confirmation for them to approve or decline again.',
    });
    await expect(validateAgentToken('ag_at_x', { scope_used: 'write:payments' })).rejects.toBeInstanceOf(ConfirmationDeclinedError);
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
    } catch (err: any) {
      expect(err).toBeInstanceOf(VerifyRefusedError);
      expect(err).not.toBeInstanceOf(ConfirmationRequiredError);
      expect(err.code).toBe('confirmation_declined');
      expect(err.declined).toEqual(DECLINED);
      expect(err.payload.declined).toEqual(DECLINED);
      expect(err.payload.error_description).toContain('declined');
      expect(err.payload.renewal).toContain('Only the user');
      expect(err.attestationStatus).toBeNull();
      expect(err.payload.confirmation).toBeUndefined();
    }
  });

  it('surfaces the attestation status when the agent retried with the declined session', async () => {
    mockFetch({
      active: true,
      error: 'confirmation_declined',
      declined: DECLINED,
      attestation_status: 'declined',
      attestation_description: 'The user declined this action.',
    });
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments', action_attestation_id: 'asess_abc' });
      throw new Error('expected refusal');
    } catch (err: any) {
      expect(err).toBeInstanceOf(ConfirmationDeclinedError);
      expect(err.attestationStatus).toBe('declined');
      expect(err.payload.attestation_description).toContain('declined');
      expect(err.payload.error_description).toContain('Do not retry');
    }
  });

  it('never passes a malformed declined block through, and still fails closed', async () => {
    mockFetch({ active: true, error: 'confirmation_declined', declined: { action_session_id: 'asess_abc', hold_until: 7 } });
    try {
      await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
      throw new Error('expected refusal');
    } catch (err: any) {
      expect(err).toBeInstanceOf(VerifyRefusedError);
      expect(err).not.toBeInstanceOf(ConfirmationDeclinedError);
      expect(err.code).toBe('confirmation_declined');
      expect(err.payload.declined).toBeUndefined();
    }
  });
});

describe('parseActionDecline', () => {
  it('requires the four string fields and nulls the optional ones', () => {
    expect(parseActionDecline({ action_session_id: 'a', declined_at: 'b', hold_until: 'c', scope: 's' })).toEqual({
      action_session_id: 'a', declined_at: 'b', hold_until: 'c', scope: 's',
      method: null, endpoint: null, request_digest: null, summary: null,
    });
    expect(parseActionDecline({ action_session_id: 'a', declined_at: 'b', scope: 's' })).toBeNull();
    expect(parseActionDecline('nope')).toBeNull();
    expect(parseActionDecline(null)).toBeNull();
  });
});

describe('retry telemetry', () => {
  it('forwards the agent attestation header, the body digest, and the action summary', async () => {
    const fetchMock = mockFetch({ active: true, user_id: 'u1', connection_id: 'c1', scopes: ['write:payments'], action_confirmation: { action_session_id: 'asess_abc', consumed: true } });
    const req = fakeReq({ headers: { [ACTION_ATTESTATION_HEADER]: ' asess_abc ' } });
    const telemetry = requestTelemetry(req, 'write:payments', { actionSummary: (r) => `Pay ${r.body.trainer} $${r.body.amount}` });
    expect(telemetry).toEqual({
      scope_used: 'write:payments',
      endpoint: '/api/payments',
      method: 'POST',
      action_attestation_id: 'asess_abc',
      request_digest: requestDigest(req),
      action_summary: 'Pay alex $50',
    });
    const ctx = await validateAgentToken('ag_at_x', telemetry);
    expect(ctx.action_confirmation).toEqual({ action_session_id: 'asess_abc', consumed: true });
    const sent = JSON.parse((fetchMock.mock.calls[0][1] as any).body);
    expect(sent.action_attestation_id).toBe('asess_abc');
    expect(sent.request_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(sent.action_summary).toBe('Pay alex $50');
  });

  it('never surfaces a malformed action_confirmation block', async () => {
    mockFetch({ active: true, user_id: 'u1', connection_id: 'c1', scopes: ['write:payments'], action_confirmation: { action_session_id: 'asess_abc', consumed: 'yes' } });
    const ctx = await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
    expect(ctx.action_confirmation).toBeUndefined();
  });

  it('omits attestation, digest, and summary when absent', () => {
    const telemetry = requestTelemetry(fakeReq({ body: undefined }), 'write:payments');
    expect(telemetry).toEqual({ scope_used: 'write:payments', endpoint: '/api/payments', method: 'POST' });
  });

  it('digest is deterministic for the same parsed body and differs for a different one', () => {
    const a = requestDigest(fakeReq());
    const b = requestDigest(fakeReq());
    const c = requestDigest(fakeReq({ body: { trainer: 'alex', amount: 500 } }));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });

  it('a summary callback that throws never blocks the call', () => {
    const telemetry = requestTelemetry(fakeReq(), 'write:payments', { actionSummary: () => { throw new Error('boom'); } });
    expect(telemetry?.action_summary).toBeUndefined();
  });
});

describe('parseActionConfirmation', () => {
  it('requires the four string fields and nulls the optional ones', () => {
    expect(parseActionConfirmation(null)).toBeNull();
    expect(parseActionConfirmation({ action_session_id: 'a' })).toBeNull();
    expect(parseActionConfirmation({ action_session_id: 'a', action_session_url: 'u', expires_at: 'e', scope: 's' })).toEqual({
      action_session_id: 'a', action_session_url: 'u', expires_at: 'e', scope: 's',
      method: null, endpoint: null, request_digest: null, summary: null,
    });
  });
});

describe('confirm_each_time scope flag', () => {
  it('round-trips from agentadmit.yaml to the scope metadata', () => {
    const byName = Object.fromEntries(getScopeMetadata().map((s) => [s.name, s]));
    expect(byName['write:payments'].confirm_each_time).toBe(true);
    expect(byName['read:workouts'].confirm_each_time).toBeUndefined();
  });

  it('is published on the /scopes endpoint the hosted service reads', async () => {
    const { agentadmitRouter } = createAgentAdmitRouter({
      storage: { storeConnection: jest.fn(), listConnections: jest.fn().mockResolvedValue([]) } as any,
      getCurrentUser: async () => ({ user_id: 'u1' }),
    });
    const app = express();
    app.use('/agentadmit', agentadmitRouter);
    const server: Server = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
    try {
      const port = (server.address() as AddressInfo).port;
      const res = await realFetch(`http://127.0.0.1:${port}/agentadmit/scopes`);
      expect(res.status).toBe(200);
      const body = await res.json() as { scopes: Array<Record<string, unknown>> };
      const payments = body.scopes.find((s) => s.name === 'write:payments');
      expect(payments?.confirm_each_time).toBe(true);
      const workouts = body.scopes.find((s) => s.name === 'read:workouts');
      expect(workouts).not.toHaveProperty('confirm_each_time');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
