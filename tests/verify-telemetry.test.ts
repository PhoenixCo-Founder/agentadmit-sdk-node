/**
 * 1.10.0 — Per-call verification telemetry + active-error fail-closed.
 *
 * Matrix (workspace projects/agentadmit/sdk-1.10.0-semantic-matrix.md):
 *   §1  verify body gains optional scope_used / endpoint / method — omitted
 *       when unknown, never null; endpoint path-only ≤500; method upper ≤20.
 *   §2  scope-aware middlewares pass the enforced scope INTO the verify call.
 *   §4  active:true + error = per-call DENIAL (403), never pass-through.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import {
  validateAgentToken,
  requireScope,
  requireScopeIfAgent,
  requestTelemetry,
} from '../src/auth';
import { VerifyRefusedError } from '../src/errors';
import { callerConsent } from '../src/callerConsent';
import { setStorage } from '../src/auth';
import { MemoryStorage } from '../src/storage';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-telemetry-test-'));
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
    '  - name: read:things',
    '    description: Read things',
    '    category: Things',
    '    role: user',
  ].join('\n'));
  return cfgPath;
}

function validBody(overrides: Record<string, any> = {}) {
  return {
    active: true,
    user_id: 'user_1',
    connection_id: 'conn_1',
    scopes: ['read:things'],
    agent_label: 'Test Agent',
    ...overrides,
  };
}

/** Mock fetch, capturing each request body. */
function mockFetchCapture(status: number, body: any): Array<Record<string, any>> {
  const captured: Array<Record<string, any>> = [];
  global.fetch = jest.fn().mockImplementation((_url: string, init: any) => {
    captured.push(JSON.parse(init.body));
    return Promise.resolve(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    );
  }) as any;
  return captured;
}

function fakeReq(path = '/api/things', method = 'get', token = 'ag_at_tok'): any {
  return {
    path,
    method,
    headers: { authorization: `Bearer ${token}` },
  };
}

function fakeRes(): any {
  const res: any = { statusCode: 0, body: null };
  res.status = (code: number) => { res.statusCode = code; return res; };
  res.json = (payload: any) => { res.body = payload; return res; };
  return res;
}

describe('1.10.0 verify telemetry + active-refusal fail-closed', () => {
  const realFetch = global.fetch;

  beforeEach(() => {
    loadConfig(writeTestConfig());
    setStorage(new MemoryStorage());
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    global.fetch = realFetch;
    jest.restoreAllMocks();
  });

  // §1/§2 — body contents
  test('requireScope sends scope_used + endpoint + method', async () => {
    const captured = mockFetchCapture(200, validBody());
    const mw = requireScope('read:things');
    const res = fakeRes();
    let nexted = false;
    await mw(fakeReq(), res, (() => { nexted = true; }) as any);
    expect(nexted).toBe(true);
    expect(captured[0]).toEqual({
      token: 'ag_at_tok',
      scope_used: 'read:things',
      endpoint: '/api/things',
      method: 'GET',
    });
  });

  test('bare validateAgentToken omits telemetry fields entirely', async () => {
    const captured = mockFetchCapture(200, validBody());
    await validateAgentToken('ag_at_tok');
    expect(captured[0]).toEqual({ token: 'ag_at_tok' });
  });

  test('requestTelemetry caps endpoint at 500 and method at 20, uppercased', () => {
    const t = requestTelemetry({ path: '/x'.repeat(400), method: 'g'.repeat(30) } as any)!;
    expect(t.endpoint!.length).toBe(500);
    expect(t.method).toBe('G'.repeat(20));
  });

  test('requestTelemetry uses req.path (query never included)', () => {
    // Express req.path excludes the query string by contract; assert we read
    // path, not url/originalUrl.
    const t = requestTelemetry({
      path: '/api/things',
      url: '/api/things?email=secret@example.com',
      originalUrl: '/api/things?email=secret@example.com',
      method: 'GET',
    } as any)!;
    expect(t.endpoint).toBe('/api/things');
  });

  test('callerConsent declares scope with hosted consent-first ordering', async () => {
    const captured = mockFetchCapture(200, validBody({
      consent: { caller_class: 'external_agent', granted: true, source: 'app_default' },
    }));
    const req = fakeReq('/api/records', 'get');
    const res = fakeRes();
    let nexted = false;
    await callerConsent({ requiredScope: 'read:things' })(
      req,
      res,
      (() => { nexted = true; }) as any,
    );
    expect(nexted).toBe(true);
    expect(captured[0]).toEqual({
      token: 'ag_at_tok',
      scope_used: 'read:things',
      endpoint: '/api/records',
      method: 'GET',
      consent_first: true,
    });
  });

  // §4 — active-error fail-closed
  test('active + bound_exceeded is a 403 denial, handler not invoked', async () => {
    mockFetchCapture(200, {
      active: true,
      error: 'bound_exceeded',
      error_description: 'The daily ceiling the user set (10 calls) has been reached.',
      bound: { window: 'daily', ceiling: 10 },
      renewal: 'Additional budget requires a new user-authorized connection.',
    });
    const mw = requireScope('read:things');
    const res = fakeRes();
    let nexted = false;
    await mw(fakeReq(), res, (() => { nexted = true; }) as any);
    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('bound_exceeded');
    expect(res.body.bound.ceiling).toBe(10);
    expect(res.body.renewal).toBeDefined();
  });

  test('active + insufficient_scope from hosted becomes 403 step-up shape', async () => {
    mockFetchCapture(200, {
      active: true,
      error: 'insufficient_scope',
      error_description: 'Scope "read:things" was not granted for this connection.',
      granted_scopes: ['read:other'],
    });
    const mw = requireScope('read:things');
    const res = fakeRes();
    await mw(fakeReq(), res, (() => {}) as any);
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({
      error: 'insufficient_scope',
      required_scope: 'read:things',
      granted_scopes: ['read:other'],
    });
  });

  test('unknown active-error fails closed with 403', async () => {
    mockFetchCapture(200, { active: true, error: 'future_refusal_class' });
    const mw = requireScopeIfAgent('read:things');
    const res = fakeRes();
    let nexted = false;
    await mw(fakeReq(), res, (() => { nexted = true; }) as any);
    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(403);
    expect(res.body.error).toBe('future_refusal_class');
  });

  test('validateAgentToken throws typed VerifyRefusedError on refusal', async () => {
    mockFetchCapture(200, { active: true, error: 'bound_exceeded' });
    await expect(validateAgentToken('ag_at_tok')).rejects.toBeInstanceOf(VerifyRefusedError);
  });

  // §5 — no behavior change without error
  test('active response without error passes through unchanged', async () => {
    mockFetchCapture(200, validBody());
    const ctx = await validateAgentToken('ag_at_tok');
    expect(ctx.scopes).toEqual(['read:things']);
  });
});
