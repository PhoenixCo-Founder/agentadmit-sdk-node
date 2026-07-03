/**
 * Tests for M5 — strict introspection response validation in validateAgentToken.
 *
 * A token is only valid when ALL of these hold:
 *   1. HTTP status is 2xx
 *   2. Body parses as JSON
 *   3. `active` is strictly boolean true (not truthy, not "true")
 *   4. Identity fields (user_id, agent_id, connection_id, sub, role, app_id, jti)
 *      are strings when present (not numbers, objects, arrays, etc.)
 *   5. `scopes` is an array of strings when present
 *
 * On type mismatch the token is treated as invalid (throws "not active").
 * The existing 429/5xx retry-then-unavailable behavior (H1/H3) must not regress.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { validateAgentToken } from '../src/auth';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-introspect-test-'));
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

/** Build a minimal valid response body */
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

function mockFetch(status: number, body: any) {
  global.fetch = jest.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  ) as any;
}

describe('validateAgentToken — introspection response validation', () => {
  const realFetch = global.fetch;

  beforeEach(() => {
    loadConfig(writeTestConfig());
    jest.spyOn(console, 'error').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    global.fetch = realFetch;
    jest.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // Baseline: a well-formed valid response succeeds
  // -------------------------------------------------------------------------

  it('accepts a fully valid response', async () => {
    mockFetch(200, validBody());
    await expect(validateAgentToken('ag_at_good')).resolves.toMatchObject({
      scopes: ['read:things'],
    });
  });

  // -------------------------------------------------------------------------
  // HTTP status enforcement
  // -------------------------------------------------------------------------

  it('rejects a non-2xx response even when body has active:true (403)', async () => {
    mockFetch(403, { active: true, user_id: 'user_1', scopes: [] });
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow();
  });

  it('rejects a non-2xx response even when body has active:true (500)', async () => {
    mockFetch(500, { active: true, user_id: 'user_1', scopes: [] });
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow();
  });

  it('rejects a non-2xx response even when body has active:true (404)', async () => {
    mockFetch(404, { active: true, user_id: 'user_1', scopes: [] });
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow();
  });

  // -------------------------------------------------------------------------
  // `active` field type strictness
  // -------------------------------------------------------------------------

  it('rejects active:false (HTTP 200)', async () => {
    mockFetch(200, { active: false, error: 'token_expired' });
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active.*token_expired/);
  });

  it('rejects active:1 (truthy number)', async () => {
    mockFetch(200, validBody({ active: 1 }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects active:"true" (string)', async () => {
    mockFetch(200, validBody({ active: 'true' }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects active:{} (object)', async () => {
    mockFetch(200, validBody({ active: {} }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  // -------------------------------------------------------------------------
  // Identity field type enforcement
  // -------------------------------------------------------------------------

  it('rejects user_id as a number', async () => {
    mockFetch(200, validBody({ user_id: 42 }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects user_id as null', async () => {
    // null user_id triggers "no user" after type check passes (null is not a string)
    mockFetch(200, validBody({ user_id: null }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow();
  });

  it('rejects user_id as an object', async () => {
    mockFetch(200, validBody({ user_id: { id: 'user_1' } }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects connection_id as a number', async () => {
    mockFetch(200, validBody({ connection_id: 99 }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects agent_id as a boolean', async () => {
    mockFetch(200, validBody({ agent_id: true }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('accepts agent_id absent (optional field)', async () => {
    // Construct body without agent_id to confirm the optional field is allowed absent
    const body: Record<string, any> = {
      active: true,
      user_id: 'user_1',
      connection_id: 'conn_1',
      scopes: ['read:things'],
      agent_label: 'Test Agent',
    };
    mockFetch(200, body);
    await expect(validateAgentToken('ag_at_good')).resolves.toBeDefined();
  });

  // -------------------------------------------------------------------------
  // `scopes` field type enforcement
  // -------------------------------------------------------------------------

  it('rejects scopes as a string instead of an array', async () => {
    mockFetch(200, validBody({ scopes: 'read:things' }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('rejects scopes array containing a non-string element', async () => {
    mockFetch(200, validBody({ scopes: ['read:things', 42] }));
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });

  it('accepts scopes as an empty array', async () => {
    mockFetch(200, validBody({ scopes: [] }));
    await expect(validateAgentToken('ag_at_good')).resolves.toMatchObject({ scopes: [] });
  });

  it('accepts scopes absent (treated as empty)', async () => {
    // Construct body without scopes field
    const body: Record<string, any> = {
      active: true,
      user_id: 'user_1',
      connection_id: 'conn_1',
      agent_label: 'Test Agent',
    };
    mockFetch(200, body);
    await expect(validateAgentToken('ag_at_good')).resolves.toMatchObject({ scopes: [] });
  });

  // -------------------------------------------------------------------------
  // Body parse failure
  // -------------------------------------------------------------------------

  it('rejects a non-JSON response body', async () => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response('not json', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' },
      }),
    ) as any;
    await expect(validateAgentToken('ag_at_bad')).rejects.toThrow(/not active/);
  });
});
