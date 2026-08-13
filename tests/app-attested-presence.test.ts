/**
 * App-attested presence: typed forwarding at token issuance.
 *
 * The requireTokenMintPresence hook may now RETURN an AppAttestedPresence to
 * allow the mint AND forward the ceremony fact to the hosted service as
 * presence {verified: true, uv: true, method, verified_at} (stored
 * provenance-marked app:<method>). Returning nothing still allows without a
 * fact; throwing still denies; any OTHER return value still fails closed
 * (500, no mint) — the v1.6.0 misconfigured-hook contract is preserved: a
 * raw object shaped exactly like the wire format is NOT an
 * AppAttestedPresence and fails closed.
 *
 * The typed class prevents a proven production-outage class by construction:
 * string timestamps must carry an explicit offset (offset-less timestamps
 * serialize ambiguously and the hosted mint rejects them with 400), and
 * method is validated against the hosted contract (^[a-z0-9_]+$, 1-60)
 * before any hosted call.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import type { AddressInfo } from 'net';
import express from 'express';

import { loadConfig } from '../src/config';
import { createAgentAdmitRouter } from '../src/routes';
import { AppAttestedPresence } from '../src/appAttestedPresence';

const HOSTED_URL = 'https://hosted.agentadmit.test';

const CEREMONY_AT = new Date('2026-08-13T17:00:00.000Z');
const WIRE = {
  verified: true,
  uv: true,
  method: 'my_webauthn',
  verified_at: '2026-08-13T17:00:00.000Z',
};

function fact(): AppAttestedPresence {
  return new AppAttestedPresence({ method: 'my_webauthn', verifiedAt: CEREMONY_AT });
}

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

// ---------------------------------------------------------------------------
// The typed class — hosted contract enforced at construction
// ---------------------------------------------------------------------------

describe('AppAttestedPresence', () => {
  it('serializes literal-true verified/uv and an offset-carrying timestamp', () => {
    expect(fact().toWire()).toEqual(WIRE);
  });

  it('accepts an ISO string that carries an explicit offset', () => {
    const p = new AppAttestedPresence({
      method: 'my_webauthn',
      verifiedAt: '2026-08-13T10:00:00-07:00',
    });
    expect(p.toWire().verified_at).toBe('2026-08-13T10:00:00-07:00');
  });

  it('rejects an offset-less timestamp string (the proven prod-outage class)', () => {
    expect(
      () => new AppAttestedPresence({ method: 'my_webauthn', verifiedAt: '2026-08-13T17:00:00' }),
    ).toThrow(/explicit offset/);
  });

  it('rejects an invalid Date and non-parsing strings', () => {
    expect(
      () => new AppAttestedPresence({ method: 'my_webauthn', verifiedAt: new Date('nope') }),
    ).toThrow(/invalid Date/);
    expect(
      () => new AppAttestedPresence({ method: 'my_webauthn', verifiedAt: 'not-a-time Z' }),
    ).toThrow(/does not parse/);
  });

  it.each([
    ['uppercase', 'My_WebAuthn'],
    ['space', 'my webauthn'],
    ['hyphen', 'my-webauthn'],
    ['empty', ''],
    ['61 chars', 'm'.repeat(61)],
  ])('rejects out-of-contract method (%s)', (_label, method) => {
    expect(() => new AppAttestedPresence({ method, verifiedAt: CEREMONY_AT })).toThrow(
      /method must be/,
    );
  });
});

// ---------------------------------------------------------------------------
// The mint route — hook return forwards / nothing omits / junk fails closed
// ---------------------------------------------------------------------------

describe('POST /connections/generate-token — app-attested presence forwarding', () => {
  let server: ReturnType<express.Express['listen']>;
  let baseUrl: string;
  let hostedCalls: Array<{ body: any }> = [];
  const realFetch = global.fetch;

  const storage: any = {
    storeConnection: jest.fn(),
    listConnections: jest.fn().mockResolvedValue([]),
    getConnection: jest.fn(),
    updateConnection: jest.fn(),
    logAccess: jest.fn(),
  };

  function startApp(requireTokenMintPresence?: any): Promise<void> {
    return new Promise((resolve) => {
      loadConfig(writeTestConfig());
      jest.clearAllMocks();
      hostedCalls = [];

      global.fetch = jest.fn(async (url: any, init?: any) => {
        if (String(url).startsWith(HOSTED_URL)) {
          hostedCalls.push({ body: init?.body ? JSON.parse(init.body) : null });
          return new Response(
            JSON.stringify({ token: 'ag_ct_new', connection_id: 'conn_1', expires_in: 3600 }),
            { status: 201, headers: { 'content-type': 'application/json' } },
          );
        }
        return realFetch(url as any, init);
      }) as any;

      const { agentadmitRouter, wellknownRouter } = createAgentAdmitRouter({
        storage,
        getCurrentUser: async () => ({ user_id: 'u1' }),
        requireTokenMintPresence,
      });
      const app = express();
      app.use(express.json());
      app.use('/agentadmit', agentadmitRouter);
      app.use(wellknownRouter);
      server = app.listen(0, () => {
        baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
        resolve();
      });
    });
  }

  function stopApp(): Promise<void> {
    return new Promise((resolve) => {
      global.fetch = realFetch;
      server.close(() => resolve());
    });
  }

  async function mint(body: Record<string, any>) {
    return realFetch(`${baseUrl}/agentadmit/connections/generate-token`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  afterEach(async () => {
    if (server) {
      await stopApp();
    } else {
      global.fetch = realFetch;
    }
  });

  it('forwards the returned fact to the hosted mint and persists it locally', async () => {
    await startApp(jest.fn(() => fact()));

    const res = await mint({ scopes: ['read:things'] });
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(200);
    expect(body.connection_token).toBe('ag_ct_new');
    expect(hostedCalls[0].body).toEqual({
      user_id: 'u1',
      scopes: ['read:things'],
      role: 'user',
      presence: WIRE,
    });
    expect(storage.storeConnection).toHaveBeenCalledTimes(1);
    expect(storage.storeConnection.mock.calls[0][0].presence).toEqual(WIRE);
  });

  it('supports async hooks resolving to a fact', async () => {
    await startApp(jest.fn(async () => fact()));

    const res = await mint({ scopes: ['read:things'] });

    expect(res.status).toBe(200);
    expect(hostedCalls[0].body.presence).toEqual(WIRE);
  });

  it('omits presence when the hook returns nothing', async () => {
    await startApp(jest.fn(() => undefined));

    const res = await mint({ scopes: ['read:things'] });

    expect(res.status).toBe(200);
    expect(hostedCalls[0].body).toEqual({ user_id: 'u1', scopes: ['read:things'], role: 'user' });
    expect(storage.storeConnection.mock.calls[0][0].presence).toBeUndefined();
  });

  it('omits presence when no hook is configured', async () => {
    await startApp(undefined);

    const res = await mint({ scopes: ['read:things'] });

    expect(res.status).toBe(200);
    expect(hostedCalls[0].body).toEqual({ user_id: 'u1', scopes: ['read:things'], role: 'user' });
  });

  it('still fails closed when the hook returns a raw wire-shaped object', async () => {
    await startApp(jest.fn(() => ({ ...WIRE })));

    const res = await mint({ scopes: ['read:things'] });
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(500);
    expect(body.error).toBe('presence_hook_misconfigured');
    expect(hostedCalls).toEqual([]);
    expect(storage.storeConnection).not.toHaveBeenCalled();
  });

  it('still denies with the thrown error when the hook throws', async () => {
    await startApp(
      jest.fn(() => {
        const err: any = new Error('Confirm human presence.');
        err.statusCode = 403;
        err.detail = { error: 'presence_attestation_required' };
        throw err;
      }),
    );

    const res = await mint({ scopes: ['read:things'] });
    const body = (await res.json()) as Record<string, any>;

    expect(res.status).toBe(403);
    expect(body.error).toBe('presence_attestation_required');
    expect(hostedCalls).toEqual([]);
    expect(storage.storeConnection).not.toHaveBeenCalled();
  });
});
