/**
 * Consent Ledger client tests.
 *
 * checkConsent must be fail-closed: any non-200 response, malformed body, or
 * network failure must throw rather than default to a granted verdict. The
 * verify passthrough must be fail-open only for the *presence* of the block
 * (old servers omit it entirely) while dropping type-malformed blocks so a
 * bad `consent` payload can never masquerade as a verdict.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { checkConsent } from '../src/consent';
import { validateAgentToken } from '../src/auth';

function writeTestConfig(extra: string[] = []): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-node-consent-test-'));
  const path = join(dir, 'agentadmit.yaml');
  writeFileSync(path, [
    'app_id: app_test',
    'app_name: Test App',
    'api_key: aa_test_dummy',
    'api_base_url: http://localhost',
    'storage:',
    '  backend: memory',
    'scopes:',
    '  - name: read:things',
    '    description: Read things',
    '    category: Things',
    '    role: user',
    ...extra,
  ].join('\n'));
  return path;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const GRANTED_VERDICT = {
  caller_class: 'in_app_ai',
  granted: true,
  scope_group: null,
  source: 'app_default',
  evaluated_at: '2026-07-03T00:00:00Z',
};

describe('checkConsent', () => {
  const realFetch = global.fetch;

  beforeEach(() => {
    loadConfig(writeTestConfig());
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    global.fetch = realFetch;
    jest.restoreAllMocks();
  });

  it('returns the verdict on 200 and posts the right request shape', async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse(GRANTED_VERDICT));
    global.fetch = fetchMock as any;

    const verdict = await checkConsent({
      appUserId: 'user_8842',
      callerClass: 'in_app_ai',
      scopeGroup: 'financial',
    });

    expect(verdict.granted).toBe(true);
    expect(verdict.caller_class).toBe('in_app_ai');
    expect(verdict.source).toBe('app_default');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.agentadmit.com/api/v1/consent/check');
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe('Bearer aa_test_dummy');
    expect(JSON.parse(init.body)).toEqual({
      app_user_id: 'user_8842',
      caller_class: 'in_app_ai',
      scope_group: 'financial',
    });
    // Timeout guard: every consent call must carry an abort signal so a hung
    // ledger endpoint cannot pin the caller's request forever.
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it('throws on non-200 with the server error detail (fail closed, no default verdict)', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ error: 'invalid_request', error_description: 'unknown app_user_id' }, 400),
    ) as any;

    await expect(
      checkConsent({ appUserId: 'nope', callerClass: 'human_session' }),
    ).rejects.toMatchObject({
      message: 'unknown app_user_id',
      status: 400,
    });
  });

  it('throws on non-200 even when the error body is unparseable', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response('<html>Bad Gateway</html>', { status: 502 }),
    ) as any;

    await expect(
      checkConsent({ appUserId: 'user_1', callerClass: 'in_app_ai' }),
    ).rejects.toMatchObject({ message: 'HTTP 502', status: 502 });
  });

  it('throws on a 200 with malformed JSON instead of returning anything', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response('{granted: definitely', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    ) as any;

    await expect(
      checkConsent({ appUserId: 'user_1', callerClass: 'in_app_ai' }),
    ).rejects.toThrow();
  });

  it('propagates network errors (fail closed on unreachable ledger)', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed')) as any;

    await expect(
      checkConsent({ appUserId: 'user_1', callerClass: 'external_agent' }),
    ).rejects.toThrow('fetch failed');
  });
});

describe('verify passthrough of the consent block', () => {
  const realFetch = global.fetch;

  const activeBody = {
    active: true,
    user_id: 'user_1',
    connection_id: 'conn_1',
    scopes: ['read:things'],
    agent_label: 'Test Agent',
  };

  beforeEach(() => {
    loadConfig(writeTestConfig());
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    global.fetch = realFetch;
    jest.restoreAllMocks();
  });

  it('parses a verify response WITHOUT a consent block; consent stays undefined', async () => {
    // Old servers never send `consent`; the SDK must not require it.
    global.fetch = jest.fn().mockResolvedValue(jsonResponse(activeBody)) as any;

    const ctx = await validateAgentToken('ag_at_dummy_token');

    expect(ctx.connection?.connection_id).toBe('conn_1');
    expect(ctx.scopes).toEqual(['read:things']);
    expect(ctx.consent).toBeUndefined();
  });

  it('passes through a well-formed embedded consent verdict', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ ...activeBody, consent: { ...GRANTED_VERDICT, caller_class: 'external_agent' } }),
    ) as any;

    const ctx = await validateAgentToken('ag_at_dummy_token');

    expect(ctx.consent).toBeDefined();
    expect(ctx.consent!.granted).toBe(true);
    expect(ctx.consent!.caller_class).toBe('external_agent');
  });

  it.each([
    ['granted is a string, not boolean', { granted: 'true', caller_class: 'in_app_ai' }],
    ['consent is a bare string', 'granted'],
    ['consent is a number', 1],
    ['consent object missing granted', { caller_class: 'in_app_ai', source: 'app_default' }],
  ])('drops a type-malformed consent block (%s) without failing verify', async (_name, badConsent) => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ ...activeBody, consent: badConsent }),
    ) as any;

    const ctx = await validateAgentToken('ag_at_dummy_token');

    // The token verdict itself must survive; the junk consent must not.
    expect(ctx.connection?.connection_id).toBe('conn_1');
    expect(ctx.consent).toBeUndefined();
  });
});
