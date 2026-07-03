/**
 * Regression tests for DELETE /connections/:id (revoke).
 *
 * Enforcement happens at the hosted service — if the hosted revoke fails,
 * the agent's token still verifies. The route previously swallowed hosted
 * failures and reported { revoked: true } anyway, which is false comfort
 * for the exact user action that most needs to be truthful.
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
  const dir = mkdtempSync(join(tmpdir(), 'aa-node-revoke-test-'));
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

describe('DELETE /connections/:id — hosted revoke must succeed before claiming revoked', () => {
  let server: ReturnType<express.Express['listen']>;
  let baseUrl: string;
  let hostedStatus = 200;
  const realFetch = global.fetch;

  const stubStorage: any = {
    storeConnection: jest.fn(),
    listConnections: jest.fn().mockResolvedValue([]),
    getConnection: jest.fn().mockResolvedValue({
      connection_id: 'conn_1',
      user_id: 'u1',
      status: 'active',
    }),
    updateConnection: jest.fn(),
    revokeConnection: jest.fn().mockResolvedValue(undefined),
    logAccess: jest.fn(),
  };

  beforeAll((done) => {
    loadConfig(writeTestConfig());

    global.fetch = jest.fn(async (url: any, init?: any) => {
      if (String(url).startsWith(HOSTED_URL)) {
        return new Response(JSON.stringify({ ok: hostedStatus < 300 }), {
          status: hostedStatus,
          headers: { 'content-type': 'application/json' },
        });
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
    jest.clearAllMocks();
    stubStorage.getConnection.mockResolvedValue({
      connection_id: 'conn_1',
      user_id: 'u1',
      status: 'active',
    });
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  async function revoke() {
    return realFetch(`${baseUrl}/agentadmit/connections/conn_1`, { method: 'DELETE' });
  }

  it('revokes locally and reports revoked:true when the hosted revoke succeeds', async () => {
    hostedStatus = 200;
    const res = await revoke();
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(200);
    expect(body.revoked).toBe(true);
    expect(stubStorage.revokeConnection).toHaveBeenCalledWith('conn_1');
  });

  it('returns 502 revoked:false and leaves the connection when the hosted revoke fails', async () => {
    hostedStatus = 500;
    const res = await revoke();
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(502);
    expect(body.revoked).toBe(false);
    expect(body.error).toBe('revoke_failed');
    expect(stubStorage.revokeConnection).not.toHaveBeenCalled();
  });

  it('treats hosted 404 as nothing-to-revoke and still revokes locally', async () => {
    hostedStatus = 404;
    const res = await revoke();
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(200);
    expect(body.revoked).toBe(true);
    expect(stubStorage.revokeConnection).toHaveBeenCalledWith('conn_1');
  });
});
