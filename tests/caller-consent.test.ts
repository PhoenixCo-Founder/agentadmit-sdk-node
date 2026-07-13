/**
 * Caller-Identity Consent middleware tests.
 *
 * The middleware must: classify the caller from credential structure before
 * any consent check; route each class to its OWN isolated path; fail closed
 * on a denied verdict or an unreachable ledger; and never let one class
 * inherit another's decision.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { callerConsent, classifyCaller } from '../src/callerConsent';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-node-callerconsent-test-'));
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
  ].join('\n'));
  return path;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}

function mockReqRes(headers: Record<string, string> = {}) {
  const req: any = { headers, params: {}, path: '/x', method: 'GET' };
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) { this.statusCode = code; return this; },
    json(payload: unknown) { this.body = payload; return this; },
  };
  let nextCalled = false;
  const next = () => { nextCalled = true; };
  return { req, res, next, wasNext: () => nextCalled };
}

const VERIFY_ACTIVE = {
  active: true,
  user_id: 'user_1',
  connection_id: 'conn_1',
  scopes: ['read:things'],
  agent_label: 'Test Agent',
};

describe('classifyCaller', () => {
  const realFetch = global.fetch;
  beforeEach(() => { loadConfig(writeTestConfig()); });
  afterEach(() => { global.fetch = realFetch; jest.restoreAllMocks(); });

  it('classifies an ag_at_ token as external_agent', () => {
    const { req } = mockReqRes({ authorization: 'Bearer ag_at_abc.def' });
    expect(classifyCaller(req)).toBe('external_agent');
  });

  it('defaults a non-agent caller to human_session', () => {
    const { req } = mockReqRes({ authorization: 'Bearer session_jwt' });
    expect(classifyCaller(req)).toBe('human_session');
  });

  it('honors classifyNonAgent for the in_app_ai class', () => {
    const { req } = mockReqRes({ 'x-internal-ai': 'secret' });
    const cls = classifyCaller(req, {
      classifyNonAgent: (r) => (r.headers['x-internal-ai'] === 'secret' ? 'in_app_ai' : 'human_session'),
    });
    expect(cls).toBe('in_app_ai');
  });
});

describe('callerConsent — external_agent path', () => {
  const realFetch = global.fetch;
  beforeEach(() => { loadConfig(writeTestConfig()); jest.spyOn(console, 'log').mockImplementation(() => {}); });
  afterEach(() => { global.fetch = realFetch; jest.restoreAllMocks(); });

  it('allows a valid agent token with the required scope', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse(VERIFY_ACTIVE)) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer ag_at_tok' });
    await callerConsent({ requiredScope: 'read:things' })(req, res, next);
    expect(wasNext()).toBe(true);
    expect(req.agentAdmit.caller_class).toBe('external_agent');
    expect(req.agentAdmit.auth_type).toBe('agent');
  });

  it('denies with 403 insufficient_scope when the scope is missing', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse(VERIFY_ACTIVE)) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer ag_at_tok' });
    await callerConsent({ requiredScope: 'write:things' })(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('insufficient_scope');
    expect(res.body.required_scope).toBe('write:things');
  });

  it('denies with 403 consent_not_granted when the embedded verdict is denied', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ ...VERIFY_ACTIVE, consent: { caller_class: 'external_agent', granted: false, source: 'setting', evaluated_at: 'x' } }),
    ) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer ag_at_tok' });
    await callerConsent()(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('consent_not_granted');
    expect(res.body.caller_class).toBe('external_agent');
  });

  it('allows when no consent block is present (platform default held)', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse(VERIFY_ACTIVE)) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer ag_at_tok' });
    await callerConsent()(req, res, next);
    expect(wasNext()).toBe(true);
  });

  it('returns 401 on an invalid agent token', async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse({ active: false, error: 'invalid_token' })) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer ag_at_bad' });
    await callerConsent()(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(401);
  });
});

describe('callerConsent — in_app_ai path', () => {
  const realFetch = global.fetch;
  beforeEach(() => { loadConfig(writeTestConfig()); });
  afterEach(() => { global.fetch = realFetch; jest.restoreAllMocks(); });

  const asInternalAi = {
    classifyNonAgent: () => 'in_app_ai' as const,
    resolveDataOwnerId: () => 'user_8842',
  };

  it('allows when the in-app-AI verdict is granted', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ caller_class: 'in_app_ai', granted: true, source: 'setting', evaluated_at: 'x' }),
    ) as any;
    const { req, res, next, wasNext } = mockReqRes({});
    await callerConsent(asInternalAi)(req, res, next);
    expect(wasNext()).toBe(true);
    expect(req.agentAdmit.caller_class).toBe('in_app_ai');
  });

  it('denies with 403 when the in-app-AI verdict is denied', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ caller_class: 'in_app_ai', granted: false, source: 'setting', evaluated_at: 'x' }),
    ) as any;
    const { req, res, next, wasNext } = mockReqRes({});
    await callerConsent(asInternalAi)(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.caller_class).toBe('in_app_ai');
  });

  it('fails closed with 503 when the ledger is unreachable', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('fetch failed')) as any;
    const { req, res, next, wasNext } = mockReqRes({});
    await callerConsent(asInternalAi)(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(503);
    expect(res.body.error).toBe('consent_unavailable');
  });

  it('returns 500 when resolveDataOwnerId is not provided', async () => {
    const { req, res, next, wasNext } = mockReqRes({});
    await callerConsent({ classifyNonAgent: () => 'in_app_ai' })(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(500);
  });
});

describe('callerConsent — human_session path', () => {
  const realFetch = global.fetch;
  beforeEach(() => { loadConfig(writeTestConfig()); });
  afterEach(() => { global.fetch = realFetch; jest.restoreAllMocks(); });

  it('defers to the app permission model by default (no ledger call)', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer session_jwt' });
    await callerConsent()(req, res, next);
    expect(wasNext()).toBe(true);
    expect(req.agentAdmit.caller_class).toBe('human_session');
    // Branch A is the app's own model: the middleware must not call the ledger.
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('gates the human path against a stored switch when gateHuman is set', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      jsonResponse({ caller_class: 'human_session', granted: false, source: 'setting', evaluated_at: 'x' }),
    ) as any;
    const { req, res, next, wasNext } = mockReqRes({ authorization: 'Bearer session_jwt' });
    await callerConsent({ gateHuman: true, resolveDataOwnerId: () => 'user_1' })(req, res, next);
    expect(wasNext()).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.caller_class).toBe('human_session');
  });
});
