/**
 * Regression tests for the /token exchange route.
 *
 * v1.1.0 coalesced absent optional agent fields to explicit JSON nulls
 * (`agent_label ?? null`), which the hosted /api/v1/exchange rejects with
 * HTTP 400 "Expected string, received null". Absent fields must be omitted.
 *
 * Also pins the discovery document's agentadmit_version to package.json
 * (it was a hand-maintained '0.1').
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { AddressInfo } from 'net';
import express from 'express';

import { loadConfig } from '../src/config';
import { createAgentAdmitRouter } from '../src/routes';

const HOSTED_URL = 'https://hosted.agentadmit.test';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-node-test-'));
  const path = join(dir, 'agentadmit.yaml');
  writeFileSync(path, [
    'app_id: app_test',
    'app_name: Test App',
    'api_key: aa_test_dummy',
    `agentadmit_api_url: ${HOSTED_URL}`,
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

const stubStorage: any = {
  storeConnection: jest.fn(),
  listConnections: jest.fn().mockResolvedValue([]),
  getConnection: jest.fn(),
  updateConnection: jest.fn(),
  logAccess: jest.fn(),
};

describe('POST /token exchange', () => {
  let server: ReturnType<express.Express['listen']>;
  let baseUrl: string;
  let captured: { body: any; headers: any } | null = null;
  const realFetch = global.fetch;

  beforeAll((done) => {
    loadConfig(writeTestConfig());

    // Intercept only hosted-service calls; let the test's own client
    // requests to localhost pass through to the real fetch.
    global.fetch = jest.fn(async (url: any, init?: any) => {
      if (String(url).startsWith(HOSTED_URL)) {
        captured = {
          body: init?.body ? JSON.parse(init.body) : null,
          headers: init?.headers ?? {},
        };
        return new Response(
          JSON.stringify({
            access_token: 'ag_at_test',
            token_type: 'Bearer',
            scopes: ['read:things'],
            connection_id: 'conn_test',
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return realFetch(url as any, init);
    }) as any;

    const { agentadmitRouter, wellknownRouter } = createAgentAdmitRouter({
      storage: stubStorage,
      getCurrentUser: async () => ({ user_id: 'u1' }),
    });
    const app = express();
    app.use(express.json());
    app.use('/agentadmit', agentadmitRouter);
    app.use(wellknownRouter);
    server = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    global.fetch = realFetch;
    server.close(done);
  });

  beforeEach(() => {
    captured = null;
  });

  async function exchange(body: Record<string, any>) {
    const res = await realFetch(`${baseUrl}/agentadmit/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    return res;
  }

  it('omits absent optional fields (hosted service rejects nulls)', async () => {
    const res = await exchange({
      grant_type: 'connection_token',
      connection_token: 'ag_ct_abc',
    });
    expect(res.status).toBe(200);
    expect(captured!.body).toEqual({ token: 'ag_ct_abc' });
    expect(Object.values(captured!.body)).not.toContain(null);
  });

  it('forwards provided optional fields', async () => {
    const res = await exchange({
      grant_type: 'connection_token',
      connection_token: 'ag_ct_abc',
      agent_label: 'My Agent',
      agent_id: 'agent_123',
      agent_metadata: { model: 'claude' },
    });
    expect(res.status).toBe(200);
    expect(captured!.body).toEqual({
      token: 'ag_ct_abc',
      agent_label: 'My Agent',
      agent_id: 'agent_123',
      agent_metadata: { model: 'claude' },
    });
  });

  it('reports the real package version in the discovery document', async () => {
    const res = await realFetch(`${baseUrl}/.well-known/agentadmit`);
    expect(res.status).toBe(200);
    const doc: any = await res.json();
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    expect(doc.agentadmit_version).toBe(require('../package.json').version);
    expect(doc.agentadmit_version).not.toBe('0.1');
  });
});
