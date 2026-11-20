/**
 * 1.15.0: confirm-each-time when the user has no passkey yet.
 *
 * Row A: `confirmation.enrollment_required` on the confirmation_required
 * refusal is kept strictly (true/false only, anything else treated as
 * absent) in the typed copy and in the 403 body, and the agent is told the
 * link alone cannot be used when it is true.
 *
 * Row B: createOwnerLink() posts to the hosted owner-link endpoint with the
 * API key and returns a typed result, never a partial one.
 */

import { mkdtempSync, readFileSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { validateAgentToken, requireScope, ENROLLMENT_REQUIRED_DESCRIPTION } from '../src/auth';
import { ConfirmationRequiredError, VerifyRefusedError } from '../src/errors';
import { createOwnerLink } from '../src/ownerLink';
import * as sdk from '../src/index';

const realFetch = global.fetch;
const OLD_DESCRIPTION =
  'This action requires a fresh human confirmation. Give the confirmation link to the user, then retry with the X-AgentAdmit-Action-Attestation header.';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-owner-link-test-'));
  const cfgPath = join(dir, 'agentadmit.yaml');
  writeFileSync(cfgPath, [
    'app_id: app_test',
    'app_name: Test App',
    'api_key: aa_test_dummy',
    'agentadmit_api_url: https://api.agentadmit.test/',
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
  ].join('\n'));
  return cfgPath;
}

const BASE_CONFIRMATION = {
  action_session_id: 'asess_abcdefghijklmnop',
  action_session_url: 'https://agentadmit.com/confirm/action/asess_abcdefghijklmnop',
  expires_at: '2026-11-20T18:30:00.000Z',
  scope: 'write:payments',
  method: 'POST',
  endpoint: '/api/payments',
  request_digest: 'sha256:deadbeef',
  summary: 'Pay Alex $50',
};

function respond(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function mockVerify(confirmation: Record<string, unknown>) {
  const fn = jest.fn().mockImplementation(() => Promise.resolve(respond(200, {
    active: true,
    error: 'confirmation_required',
    confirmation,
  })));
  global.fetch = fn as any;
  return fn;
}

async function refusal(): Promise<ConfirmationRequiredError> {
  try {
    await validateAgentToken('ag_at_x', { scope_used: 'write:payments' });
  } catch (err: any) {
    return err;
  }
  throw new Error('expected refusal');
}

/** The 403 body requireScope actually sends, serialized as Express would. */
async function sent403(): Promise<{ status: number; body: any }> {
  let status = 0;
  let json: unknown;
  const res: any = {
    status(code: number) { status = code; return res; },
    json(body: unknown) { json = body; return res; },
  };
  const req: any = { path: '/api/payments', method: 'POST', headers: { authorization: 'Bearer ag_at_x' }, body: {} };
  await requireScope('write:payments')(req, res, () => { throw new Error('next() must not run'); });
  return { status, body: JSON.parse(JSON.stringify(json)) };
}

beforeAll(() => { loadConfig(writeTestConfig()); });
afterEach(() => { global.fetch = realFetch; });

describe('Row A: confirmation.enrollment_required', () => {
  it.each([
    ['true', true, true],
    ['false', false, false],
  ])('wire %s is kept as a boolean in the typed copy and the 403 body', async (_label, wire, expected) => {
    mockVerify({ ...BASE_CONFIRMATION, enrollment_required: wire });
    const err = await refusal();
    expect(err).toBeInstanceOf(ConfirmationRequiredError);
    expect(err.confirmation.enrollment_required).toBe(expected);
    expect((err.payload.confirmation as any).enrollment_required).toBe(expected);
    const { status, body } = await sent403();
    expect(status).toBe(403);
    expect(body.confirmation.enrollment_required).toBe(expected);
  });

  it.each([
    ['absent', undefined],
    ['null', null],
    ['the string "true"', 'true'],
    ['1', 1],
    ['0', 0],
    ['{}', {}],
    ['[]', []],
  ])('wire %s is treated as absent, never coerced', async (_label, wire) => {
    const confirmation: Record<string, unknown> = { ...BASE_CONFIRMATION };
    if (wire !== undefined) confirmation.enrollment_required = wire;
    mockVerify(confirmation);
    const err = await refusal();
    expect(err).toBeInstanceOf(ConfirmationRequiredError);
    expect('enrollment_required' in err.confirmation).toBe(false);
    expect(err.confirmation).toEqual(BASE_CONFIRMATION);
    const { status, body } = await sent403();
    expect(status).toBe(403);
    expect(body.confirmation).toEqual(BASE_CONFIRMATION);
    expect('enrollment_required' in body.confirmation).toBe(false);
  });

  it('a block missing action_session_url is still dropped whole', async () => {
    const { action_session_url: _drop, ...rest } = BASE_CONFIRMATION;
    mockVerify({ ...rest, enrollment_required: true });
    const err = await refusal();
    expect(err).toBeInstanceOf(VerifyRefusedError);
    expect(err).not.toBeInstanceOf(ConfirmationRequiredError);
    expect(err.payload.confirmation).toBeUndefined();
    const { body } = await sent403();
    expect(body.confirmation).toBeUndefined();
    expect(body.error_description).toBe(OLD_DESCRIPTION);
  });

  it('tells the agent the link alone cannot be used only when enrollment_required is true', async () => {
    expect(ENROLLMENT_REQUIRED_DESCRIPTION).toBe(
      'This action requires a fresh human confirmation, and this user has no passkey on file for the app yet, so the confirmation link alone cannot be used. Ask the user to open the request from inside the app. After they confirm, retry with the X-AgentAdmit-Action-Attestation header.',
    );
    mockVerify({ ...BASE_CONFIRMATION, enrollment_required: true });
    expect((await sent403()).body.error_description).toBe(ENROLLMENT_REQUIRED_DESCRIPTION);

    mockVerify({ ...BASE_CONFIRMATION, enrollment_required: false });
    expect((await sent403()).body.error_description).toBe(OLD_DESCRIPTION);

    mockVerify({ ...BASE_CONFIRMATION });
    expect((await sent403()).body.error_description).toBe(OLD_DESCRIPTION);
  });
});

describe('Row B: createOwnerLink', () => {
  const ID = 'asess_abc-DEF_ghijklmnop';
  const OWNER_URL = 'https://agentadmit.com/confirm/action/asess_abc-DEF_ghijklmnop#olt_secretsecret';

  function mockHosted(status: number, body: unknown) {
    const fn = jest.fn().mockImplementation(() => Promise.resolve(respond(status, body)));
    global.fetch = fn as any;
    return fn;
  }

  it('is exported from the package entry and not mounted on the router', () => {
    expect(typeof sdk.createOwnerLink).toBe('function');
    const routesSource = readFileSync(join(__dirname, '..', 'src', 'routes.ts'), 'utf8');
    expect(routesSource).not.toMatch(/owner.?link/i);
  });

  it('posts the app user id with the API key to the URL-encoded path', async () => {
    const encodeSpy = jest.spyOn(global, 'encodeURIComponent');
    const fn = mockHosted(201, {
      action_session_id: ID,
      owner_session_url: OWNER_URL,
      enrollment_required: true,
      enrollment_reason: 'no_passkey',
      expires_at: '2026-11-20T18:30:00.000Z',
    });
    const link = await createOwnerLink(ID, 'user_42');
    expect(encodeSpy).toHaveBeenCalledWith(ID);
    encodeSpy.mockRestore();
    expect(fn).toHaveBeenCalledTimes(1);
    const [url, init] = fn.mock.calls[0];
    expect(url).toBe(`https://api.agentadmit.test/api/v1/action-sessions/${encodeURIComponent(ID)}/owner-link`);
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer aa_test_dummy');
    expect(init.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(init.body)).toEqual({ app_user_id: 'user_42' });
    expect(link).toEqual({
      action_session_id: ID,
      owner_session_url: OWNER_URL,
      enrollment_required: true,
      enrollment_reason: 'no_passkey',
      expires_at: '2026-11-20T18:30:00.000Z',
    });
  });

  it('encodes characters a path cannot carry', async () => {
    const fn = mockHosted(200, { action_session_id: 'x', owner_session_url: 'u', enrollment_required: false, expires_at: 'e' });
    await createOwnerLink('asess_a/b?c#d e_ghijklmn', 'user_42');
    expect(fn.mock.calls[0][0]).toBe('https://api.agentadmit.test/api/v1/action-sessions/asess_a%2Fb%3Fc%23d%20e_ghijklmn/owner-link');
  });

  it('returns the ordinary link on 200 with no enrollment_reason', async () => {
    mockHosted(200, {
      action_session_id: ID,
      owner_session_url: 'https://agentadmit.com/confirm/action/asess_abc-DEF_ghijklmnop',
      enrollment_required: false,
      expires_at: '2026-11-20T18:30:00.000Z',
    });
    const link = await createOwnerLink(ID, 'user_42');
    expect(link.enrollment_required).toBe(false);
    expect('enrollment_reason' in link).toBe(false);
    expect(link.owner_session_url).toBe('https://agentadmit.com/confirm/action/asess_abc-DEF_ghijklmnop');
  });

  it.each([
    [401, 'invalid_api_key'],
    [403, 'api_key_not_app_linked'],
    [404, 'not_found'],
    [409, 'already_consumed'],
    [409, 'already_verified'],
    [410, 'session_expired'],
    [429, 'rate_limited'],
  ])('maps HTTP %i %s to an error with status and code, no retry', async (status, code) => {
    const fn = mockHosted(status, { error: code });
    const err: any = await createOwnerLink(ID, 'user_42').catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.status).toBe(status);
    expect(err.code).toBe(code);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('surfaces a 5xx as an error with its status', async () => {
    mockHosted(500, { error: 'internal_error' });
    const err: any = await createOwnerLink(ID, 'user_42').catch((e) => e);
    expect(err.status).toBe(500);
    expect(err.code).toBe('internal_error');
  });

  it.each([
    ['bad prefix', 'sess_abcdefghijklmnopqrst', 'user_42'],
    ['too short', 'asess_short', 'user_42'],
    ['not a string', 42 as any, 'user_42'],
    ['empty user', ID, ''],
    ['user over 255', ID, 'u'.repeat(256)],
  ])('rejects %s before any network call', async (_label, id, user) => {
    const fn = mockHosted(201, {});
    await expect(createOwnerLink(id, user)).rejects.toBeInstanceOf(TypeError);
    expect(fn).not.toHaveBeenCalled();
  });

  it('accepts a 255-character user id', async () => {
    mockHosted(200, { action_session_id: ID, owner_session_url: 'u', enrollment_required: false, expires_at: 'e' });
    await expect(createOwnerLink(ID, 'u'.repeat(255))).resolves.toBeDefined();
  });

  it.each([
    ['no owner_session_url', { action_session_id: ID, enrollment_required: true, expires_at: 'e' }],
    ['owner_session_url not a string', { action_session_id: ID, owner_session_url: 7, enrollment_required: true, expires_at: 'e' }],
    ['no enrollment_required', { action_session_id: ID, owner_session_url: OWNER_URL, expires_at: 'e' }],
    ['enrollment_required as a string', { action_session_id: ID, owner_session_url: OWNER_URL, enrollment_required: 'true', expires_at: 'e' }],
    ['not an object', [OWNER_URL]],
  ])('a 2xx with %s is a malformed-response error, never a partial result', async (_label, body) => {
    mockHosted(201, body);
    const err: any = await createOwnerLink(ID, 'user_42').catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/Malformed/);
    expect(err.code).toBeNull();
    expect(JSON.stringify(err.data)).not.toContain('olt_');
    expect(err.message).not.toContain('olt_');
  });

  it('never logs or puts the owner link into an error', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map((m) => jest.spyOn(console, m).mockImplementation(() => {}));
    mockHosted(201, { action_session_id: ID, owner_session_url: OWNER_URL, enrollment_required: true, enrollment_reason: 'no_passkey', expires_at: 'e' });
    await createOwnerLink(ID, 'user_42');
    mockHosted(201, { action_session_id: ID, owner_session_url: OWNER_URL, expires_at: 'e' });
    const err: any = await createOwnerLink(ID, 'user_42').catch((e) => e);
    expect(String(err.message)).not.toContain('olt_');
    for (const spy of spies) {
      for (const call of spy.mock.calls) expect(JSON.stringify(call)).not.toContain('olt_');
      spy.mockRestore();
    }
  });
});
