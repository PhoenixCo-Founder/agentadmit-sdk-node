/**
 * Tests for declared purpose (v1.7.0).
 *
 * Declared purpose: the user-facing reason recorded on the grant at the
 * consent moment. Review-time record only, never an enforcement input;
 * authorization decisions ride scopes, connection status, and consent.
 *
 * Router side — POST /connections/generate-token:
 *   - forwards `purpose` to the hosted mint body when provided
 *   - OMITS the `purpose` key when absent (hosted contract: optional field)
 *   - rejects a 301-char purpose with 400 invalid_request before any hosted
 *     call or local write (contract is 1..300 chars)
 *   - persists `purpose` in the LOCAL connection store at mint time so the
 *     GET /connections listing (served from local storage) carries it;
 *     absent/null → absent from the stored record and the listing JSON
 * Verify side — validateAgentToken:
 *   - passes a string `purpose` through to the context
 *   - treats wire `null` / absent as "none declared" (context field absent)
 *   - VerifyActive type carries `purpose?: string | null` (compile check)
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { AddressInfo } from 'net';
import express from 'express';

import { loadConfig } from '../src/config';
import { createAgentAdmitRouter } from '../src/routes';
import { MemoryStorage } from '../src/storage';
import { validateAgentToken } from '../src/auth';
import type { VerifyActive } from '../src/auth';

const HOSTED_URL = 'https://hosted.agentadmit.test';

function writeTestConfig(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-purpose-test-'));
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

describe('POST /connections/generate-token — declared purpose', () => {
  let server: ReturnType<express.Express['listen']>;
  let baseUrl: string;
  let hostedCalls: Array<{ body: any; headers: any }> = [];
  const realFetch = global.fetch;

  const storage: any = {
    storeConnection: jest.fn(),
    listConnections: jest.fn().mockResolvedValue([]),
    getConnection: jest.fn(),
    updateConnection: jest.fn(),
    logAccess: jest.fn(),
  };

  beforeAll((done) => {
    loadConfig(writeTestConfig());

    // Intercept only hosted-service calls; let the test's own client
    // requests to localhost pass through to the real fetch.
    global.fetch = jest.fn(async (url: any, init?: any) => {
      if (String(url).startsWith(HOSTED_URL)) {
        hostedCalls.push({
          body: init?.body ? JSON.parse(init.body) : null,
          headers: init?.headers ?? {},
        });
        return new Response(
          JSON.stringify({
            token: 'ag_ct_new',
            connection_id: 'conn_1',
            expires_in: 3600,
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      }
      return realFetch(url as any, init);
    }) as any;

    const { agentadmitRouter, wellknownRouter } = createAgentAdmitRouter({
      storage,
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
    hostedCalls = [];
    jest.clearAllMocks();
  });

  async function mint(body: Record<string, any>) {
    return realFetch(`${baseUrl}/agentadmit/connections/generate-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  it('forwards purpose to the hosted mint when provided', async () => {
    const res = await mint({
      scopes: ['read:things'],
      purpose: 'Reconcile July invoices',
    });
    expect(res.status).toBe(200);
    expect(hostedCalls).toHaveLength(1);
    expect(hostedCalls[0].body).toEqual({
      user_id: 'u1',
      scopes: ['read:things'],
      role: 'user',
      purpose: 'Reconcile July invoices',
    });
    // Local store write carries the declared purpose too — the admin panel's
    // GET /connections listing is served from local storage, not the hosted mint.
    expect(storage.storeConnection).toHaveBeenCalledWith(
      expect.objectContaining({ purpose: 'Reconcile July invoices' }),
    );
  });

  it('omits the purpose key when not provided', async () => {
    const res = await mint({ scopes: ['read:things'] });
    expect(res.status).toBe(200);
    expect(hostedCalls).toHaveLength(1);
    expect(hostedCalls[0].body).toEqual({
      user_id: 'u1',
      scopes: ['read:things'],
      role: 'user',
    });
    expect('purpose' in hostedCalls[0].body).toBe(false);
    // Local store write: no declared purpose → undefined (JSON-omitted).
    expect(storage.storeConnection).toHaveBeenCalledTimes(1);
    expect(storage.storeConnection.mock.calls[0][0].purpose).toBeUndefined();
  });

  it('accepts a purpose at the 300-char boundary', async () => {
    const purpose = 'p'.repeat(300);
    const res = await mint({ scopes: ['read:things'], purpose });
    expect(res.status).toBe(200);
    expect(hostedCalls[0].body.purpose).toBe(purpose);
  });

  it('rejects a 301-char purpose with 400 invalid_request, before any hosted call or local write', async () => {
    const res = await mint({ scopes: ['read:things'], purpose: 'p'.repeat(301) });
    const body = await res.json() as Record<string, any>;

    expect(res.status).toBe(400);
    expect(body.error).toBe('invalid_request');
    expect(hostedCalls).toEqual([]);
    expect(storage.storeConnection).not.toHaveBeenCalled();
  });

  it('rejects a non-string purpose with 400 invalid_request', async () => {
    for (const bad of [42, {}, ['p'], true] as any[]) {
      const res = await mint({ scopes: ['read:things'], purpose: bad });
      const body = await res.json() as Record<string, any>;
      expect(res.status).toBe(400);
      expect(body.error).toBe('invalid_request');
    }
    expect(hostedCalls).toEqual([]);
    expect(storage.storeConnection).not.toHaveBeenCalled();
  });
});

describe('local connection store + GET /connections — declared purpose', () => {
  let server: ReturnType<express.Express['listen']>;
  let baseUrl: string;
  let storage: MemoryStorage;
  let nextConnId = 0;
  const realFetch = global.fetch;

  beforeAll((done) => {
    loadConfig(writeTestConfig());
    storage = new MemoryStorage();

    // Intercept only hosted-service calls; each mint gets a distinct
    // connection_id so records don't collide in the local store.
    global.fetch = jest.fn(async (url: any, init?: any) => {
      if (String(url).startsWith(HOSTED_URL)) {
        nextConnId += 1;
        return new Response(
          JSON.stringify({
            token: 'ag_ct_new',
            connection_id: `conn_${nextConnId}`,
            expires_in: 3600,
          }),
          { status: 201, headers: { 'content-type': 'application/json' } },
        );
      }
      return realFetch(url as any, init);
    }) as any;

    const { agentadmitRouter, wellknownRouter } = createAgentAdmitRouter({
      storage,
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

  async function mint(body: Record<string, any>) {
    return realFetch(`${baseUrl}/agentadmit/connections/generate-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  async function listConnections(): Promise<Record<string, any>[]> {
    const res = await realFetch(`${baseUrl}/agentadmit/connections`);
    expect(res.status).toBe(200);
    const body = await res.json() as Record<string, any>;
    return body.connections;
  }

  it('persists purpose in the local store at mint so the listing carries it', async () => {
    const before = (await storage.listConnections('u1')).length;
    const res = await mint({
      scopes: ['read:things'],
      purpose: 'Reconcile July invoices',
    });
    expect(res.status).toBe(200);

    // Local store record carries the declared purpose.
    const records = await storage.listConnections('u1');
    expect(records).toHaveLength(before + 1);
    const record = records[before];
    expect(record.purpose).toBe('Reconcile July invoices');

    // ...and it survives to the GET /connections listing JSON.
    const listed = await listConnections();
    const conn = listed.find(c => c.connection_id === record.connection_id)!;
    expect(conn.purpose).toBe('Reconcile July invoices');
  });

  it('mint without purpose (or explicit null) → absent from the record and the listing', async () => {
    for (const body of [
      { scopes: ['read:things'] },
      { scopes: ['read:things'], purpose: null },
    ]) {
      const before = (await storage.listConnections('u1')).length;
      const res = await mint(body);
      expect(res.status).toBe(200);

      const record = (await storage.listConnections('u1'))[before];
      expect(record.purpose).toBeUndefined();

      const listed = await listConnections();
      const conn = listed.find(c => c.connection_id === record.connection_id)!;
      expect('purpose' in conn).toBe(false);
    }
  });
});

describe('validateAgentToken — declared purpose', () => {
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

  function mockFetch(status: number, body: any) {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ) as any;
  }

  beforeEach(() => {
    loadConfig(writeTestConfig());
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('passes a declared purpose through to the context', async () => {
    mockFetch(200, validBody({ purpose: 'Reconcile July invoices' }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.purpose).toBe('Reconcile July invoices');
  });

  it('treats wire null as none declared (context field absent)', async () => {
    mockFetch(200, validBody({ purpose: null }));
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.purpose).toBeUndefined();
    expect('purpose' in ctx).toBe(false);
  });

  it('omits purpose when the server does not send it (older servers)', async () => {
    mockFetch(200, validBody());
    const ctx = await validateAgentToken('ag_at_x');
    expect(ctx.purpose).toBeUndefined();
  });

  it('VerifyActive type carries nullable purpose (compile check)', () => {
    // Type-level assertion: both a string and an explicit null must be
    // assignable, mirroring the hosted /verify wire contract.
    const withPurpose: VerifyActive = {
      active: true,
      user_id: 'user_1',
      purpose: 'Reconcile July invoices',
    };
    const withNull: VerifyActive = {
      active: true,
      user_id: 'user_1',
      purpose: null,
    };
    expect(withPurpose.purpose).toBe('Reconcile July invoices');
    expect(withNull.purpose).toBeNull();
  });
});
