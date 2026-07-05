/**
 * Tests for the presence block (WebAuthn human-presence step-up, server
 * Phase 2). validateAgentToken must:
 *   - attach `presence` when the platform returns a well-formed block
 *   - omit it when absent (older servers) or malformed (strictness mirrors
 *     the consent block: `verified` must be strictly boolean)
 * presenceVerified() must be strict: only `verified: true` counts.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { validateAgentToken, presenceVerified } from '../src/auth';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-presence-test-'));
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

function mockFetch(status: number, body: any) {
  global.fetch = jest.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  ) as any;
}

describe('validateAgentToken — presence block', () => {
  const realFetch = global.fetch;

  beforeEach(() => {
    loadConfig(writeTestConfig());
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('attaches a verified presence block', async () => {
    mockFetch(200, validBody({
      presence: { verified: true, method: 'webauthn', uv: true, verified_at: '2026-07-05T00:00:00Z' },
    }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.presence).toEqual({
      verified: true, method: 'webauthn', uv: true, verified_at: '2026-07-05T00:00:00Z',
    });
    expect(presenceVerified(ctx)).toBe(true);
  });

  it('attaches an unverified presence block (presence-off connection)', async () => {
    mockFetch(200, validBody({
      presence: { verified: false, method: null, uv: null, verified_at: null },
    }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.presence?.verified).toBe(false);
    expect(presenceVerified(ctx)).toBe(false);
  });

  it('omits presence when the server does not send it (older servers)', async () => {
    mockFetch(200, validBody());
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.presence).toBeUndefined();
    expect(presenceVerified(ctx)).toBe(false);
  });

  it('rejects a coerced verified flag — strictly boolean, like active', async () => {
    for (const bad of ['true', 1, {}, []] as any[]) {
      mockFetch(200, validBody({ presence: { verified: bad } }));
      const ctx = await validateAgentToken('ag_at_x');
      expect(ctx.presence).toBeUndefined();
      expect(presenceVerified(ctx)).toBe(false);
    }
  });

  it('ignores a non-object presence value', async () => {
    mockFetch(200, validBody({ presence: 'verified' }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.presence).toBeUndefined();
    expect(presenceVerified(ctx)).toBe(false);
  });
});
