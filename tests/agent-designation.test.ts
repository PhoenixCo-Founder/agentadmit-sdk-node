/**
 * Tests for agent designation on the verify context (v1.14.0).
 *
 * On AgentAdmit's consent page the user says which agent app a connection is
 * for and, optionally, which AI model family it mainly uses. Separately, the
 * agent may report its own platform and model when it redeems the connection
 * token. The hosted /verify response carries both:
 *
 *   designated_agent: { agent_id, name, source: 'user_declared', model } | null
 *   agent_reported:   { platform, model: { id, version } } | null
 *
 * Semantic matrix (identical in every server SDK):
 *   - a well-formed designated_agent reaches the context unchanged
 *   - null / absent / malformed (no name, wrong source, not an object) →
 *     context field absent, never coerced
 *   - a typed name has agent_id null; a model with no listed id has
 *     model_id null; a malformed model is dropped and the app is kept
 *   - agent_reported reaches the context when it has a string platform or a
 *     model with a string id; version is null when not a string
 *   - agent_reported with neither is absent
 *   - both are review-time records: nothing in the SDK branches on them
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { validateAgentToken, parseDesignatedAgent, parseAgentReported } from '../src/auth';
import type { VerifyActive, DesignatedAgent, AgentReported } from '../src/auth';
import * as sdk from '../src/index';

const HOSTED_URL = 'https://hosted.agentadmit.test';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-designation-test-'));
  const path = join(dir, 'agentadmit.yaml');
  writeFileSync(path, [
    'app_id: app_test',
    'app_name: Test App',
    'api_key: aa_test_dummy',
    `agentadmit_api_url: ${HOSTED_URL}`,
    `agentadmit_verify_url: ${HOSTED_URL}/api/v1/verify`,
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
  return path;
}

const LISTED: DesignatedAgent = {
  agent_id: 'agt_openclaw',
  name: 'OpenClaw',
  source: 'user_declared',
  model: { model_id: 'agt_claude', name: 'Claude (Anthropic)' },
};

describe('validateAgentToken — agent designation', () => {
  const realFetch = global.fetch;

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

  function mockFetch(body: any) {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } }),
    ) as any;
  }

  beforeEach(() => { loadConfig(writeTestConfig()); });
  afterEach(() => { global.fetch = realFetch; });

  it('passes the user designation through to the context', async () => {
    mockFetch(validBody({ designated_agent: LISTED }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.designated_agent).toEqual(LISTED);
  });

  it('keeps the agent label (reported by the agent) separate from the designation', async () => {
    mockFetch(validBody({ agent_label: 'Claude Code 2.1', designated_agent: LISTED }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.connection?.agent_label).toBe('Claude Code 2.1');
    expect(ctx.designated_agent?.name).toBe('OpenClaw');
  });

  it('a typed name has a null agent_id, and no model is null', async () => {
    mockFetch(validBody({ designated_agent: { agent_id: null, name: 'My research agent', source: 'user_declared', model: null } }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.designated_agent).toEqual({ agent_id: null, name: 'My research agent', source: 'user_declared', model: null });
  });

  it('treats wire null as no designation (context field absent)', async () => {
    mockFetch(validBody({ designated_agent: null, agent_reported: null }));
    const ctx = await validateAgentToken('ag_at_x');
    expect('designated_agent' in ctx).toBe(false);
    expect('agent_reported' in ctx).toBe(false);
  });

  it('omits both when the server does not send them (older servers)', async () => {
    mockFetch(validBody());
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.designated_agent).toBeUndefined();
    expect(ctx.agent_reported).toBeUndefined();
  });

  it('passes what the agent reported about itself through to the context', async () => {
    mockFetch(validBody({ agent_reported: { platform: 'OpenClaw 2026.6', model: { id: 'example-model', version: '2026-01' } } }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.agent_reported).toEqual({ platform: 'OpenClaw 2026.6', model: { id: 'example-model', version: '2026-01' } });
  });

  it('carries both records independently on the same context', async () => {
    mockFetch(validBody({ designated_agent: LISTED, agent_reported: { platform: null, model: { id: 'gpt-x', version: null } } }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.designated_agent?.model?.name).toBe('Claude (Anthropic)');
    expect(ctx.agent_reported).toEqual({ platform: null, model: { id: 'gpt-x', version: null } });
  });

  it('a malformed designation never reaches the context and never fails the call', async () => {
    for (const bad of ['OpenClaw', 7, [], {}, { name: '' }, { name: 5, source: 'user_declared' }, { name: 'OpenClaw' }, { name: 'OpenClaw', source: 'operator_verified' }]) {
      mockFetch(validBody({ designated_agent: bad }));
      const ctx = await validateAgentToken('ag_at_x');
      expect('designated_agent' in ctx).toBe(false);
      expect(ctx.scopes).toEqual(['read:things']);
    }
  });
});

describe('parseDesignatedAgent', () => {
  it('reads a listed app and model', () => {
    expect(parseDesignatedAgent({ ...LISTED, extra: 'dropped' })).toEqual(LISTED);
  });
  it('a malformed model is dropped and the app is kept', () => {
    for (const badModel of ['Grok', 3, {}, { name: '' }, { name: 9 }, { model_id: 'agt_x' }]) {
      expect(parseDesignatedAgent({ agent_id: 'agt_1', name: 'Hermes', source: 'user_declared', model: badModel }))
        .toEqual({ agent_id: 'agt_1', name: 'Hermes', source: 'user_declared', model: null });
    }
  });
  it('a model named by the user without a listed id has a null model_id', () => {
    expect(parseDesignatedAgent({ agent_id: 'agt_1', name: 'OpenClaw', source: 'user_declared', model: { name: 'Mistral' } })?.model)
      .toEqual({ model_id: null, name: 'Mistral' });
  });
  it('returns null for anything that is not a user-declared designation', () => {
    for (const bad of [null, undefined, 'x', 1, [], {}, { name: 'x' }, { name: 'x', source: 'agent_reported' }]) {
      expect(parseDesignatedAgent(bad)).toBeNull();
    }
  });
});

describe('parseAgentReported', () => {
  it('reads platform and model', () => {
    expect(parseAgentReported({ platform: 'ExampleAgent 2.1', model: { id: 'example-model', version: '2026-01' } }))
      .toEqual({ platform: 'ExampleAgent 2.1', model: { id: 'example-model', version: '2026-01' } });
  });
  it('platform only, model only, and a non-string version', () => {
    expect(parseAgentReported({ platform: 'ExampleAgent' })).toEqual({ platform: 'ExampleAgent', model: null });
    expect(parseAgentReported({ model: { id: 'm1' } })).toEqual({ platform: null, model: { id: 'm1', version: null } });
    expect(parseAgentReported({ model: { id: 'm1', version: 3 } })).toEqual({ platform: null, model: { id: 'm1', version: null } });
  });
  it('returns null when it carries neither a platform nor a model id', () => {
    for (const bad of [null, undefined, 'x', 1, [], {}, { platform: 5 }, { platform: '' }, { model: {} }, { model: { version: '1' } }, { platform: null, model: null }]) {
      expect(parseAgentReported(bad)).toBeNull();
    }
  });
});

describe('types and exports', () => {
  it('VerifyActive carries nullable designated_agent and agent_reported (compile check)', () => {
    const withBoth: VerifyActive = {
      active: true,
      user_id: 'user_1',
      designated_agent: LISTED,
      agent_reported: { platform: 'x', model: null } as AgentReported,
    };
    const withNull: VerifyActive = { active: true, user_id: 'user_1', designated_agent: null, agent_reported: null };
    expect(withBoth.active && withNull.active).toBe(true);
  });
  it('the readers are exported from the package entry', () => {
    expect(typeof sdk.parseDesignatedAgent).toBe('function');
    expect(typeof sdk.parseAgentReported).toBe('function');
  });
});
