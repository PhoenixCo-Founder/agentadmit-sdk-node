/**
 * Tests for M4 — HTTPS scheme enforcement on agentadmit_api_url and
 * agentadmit_verify_url at loadConfig() time.
 *
 * Rules:
 *   - https:// is always allowed.
 *   - http:// is allowed only when the host is localhost, 127.0.0.1, or [::1].
 *   - http:// with any other host is rejected with a clear configuration error.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { validateUrlScheme, loadConfig } from '../src/config';

// ---------------------------------------------------------------------------
// Unit tests for the helper itself
// ---------------------------------------------------------------------------

describe('validateUrlScheme helper', () => {
  it('accepts https:// URLs', () => {
    expect(() => validateUrlScheme('https://api.agentadmit.com', 'test')).not.toThrow();
    expect(() => validateUrlScheme('https://api.agentadmit.com/api/v1/verify', 'test')).not.toThrow();
  });

  it('accepts http://localhost (local dev exception)', () => {
    expect(() => validateUrlScheme('http://localhost:3000', 'test')).not.toThrow();
    expect(() => validateUrlScheme('http://localhost', 'test')).not.toThrow();
  });

  it('accepts http://127.0.0.1 (local dev exception)', () => {
    expect(() => validateUrlScheme('http://127.0.0.1:8080', 'test')).not.toThrow();
    expect(() => validateUrlScheme('http://127.0.0.1', 'test')).not.toThrow();
  });

  it('accepts http://[::1] (local dev exception)', () => {
    expect(() => validateUrlScheme('http://[::1]:9000', 'test')).not.toThrow();
  });

  it('rejects http:// with a non-localhost host', () => {
    expect(() => validateUrlScheme('http://api.agentadmit.com', 'agentadmit_api_url')).toThrow(
      /Configuration error.*agentadmit_api_url.*https/,
    );
  });

  it('rejects http:// with an IP that is not 127.0.0.1', () => {
    expect(() => validateUrlScheme('http://192.168.1.1', 'field')).toThrow(/Configuration error/);
  });

  it('includes the field name and scheme in the error message', () => {
    let msg = '';
    try {
      validateUrlScheme('http://example.com', 'agentadmit_verify_url');
    } catch (err: any) {
      msg = err.message;
    }
    expect(msg).toContain('agentadmit_verify_url');
    expect(msg).toContain('https://');
  });
});

// ---------------------------------------------------------------------------
// Integration: loadConfig() enforces scheme on the URL fields
// ---------------------------------------------------------------------------

function writeConfig(overrides: Record<string, string> = {}): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-url-scheme-test-'));
  const cfgPath = join(dir, 'agentadmit.yaml');

  const base = {
    app_id: 'app_test',
    app_name: 'Test App',
    api_key: 'aa_test_dummy',
    agentadmit_api_url: 'https://api.agentadmit.com',
    agentadmit_verify_url: 'https://api.agentadmit.com/api/v1/verify',
    api_base_url: 'http://localhost',
    storage: { backend: 'memory' },
    scopes: [],
    ...overrides,
  };

  // Serialize: handle nested objects with simple YAML
  const lines: string[] = [];
  for (const [k, v] of Object.entries(base)) {
    if (typeof v === 'object' && !Array.isArray(v)) {
      lines.push(`${k}:`);
      for (const [sk, sv] of Object.entries(v as Record<string, any>)) {
        lines.push(`  ${sk}: ${sv}`);
      }
    } else if (Array.isArray(v)) {
      lines.push(`${k}: []`);
    } else {
      lines.push(`${k}: ${v}`);
    }
  }
  writeFileSync(cfgPath, lines.join('\n'));
  return cfgPath;
}

describe('loadConfig URL scheme enforcement', () => {
  it('loads successfully with https:// URLs', () => {
    expect(() => loadConfig(writeConfig())).not.toThrow();
  });

  it('loads successfully with http://localhost for api base (not validated) and https for hosted URLs', () => {
    expect(() =>
      loadConfig(writeConfig({ api_base_url: 'http://localhost:3000' })),
    ).not.toThrow();
  });

  it('rejects http:// agentadmit_api_url pointing at a remote host', () => {
    expect(() =>
      loadConfig(writeConfig({ agentadmit_api_url: 'http://api.agentadmit.com' })),
    ).toThrow(/Configuration error.*agentadmit_api_url/);
  });

  it('rejects http:// agentadmit_verify_url pointing at a remote host', () => {
    expect(() =>
      loadConfig(writeConfig({ agentadmit_verify_url: 'http://api.agentadmit.com/api/v1/verify' })),
    ).toThrow(/Configuration error.*agentadmit_verify_url/);
  });

  it('allows http://localhost for agentadmit_api_url (local dev)', () => {
    expect(() =>
      loadConfig(writeConfig({ agentadmit_api_url: 'http://localhost:4000' })),
    ).not.toThrow();
  });

  it('allows http://127.0.0.1 for agentadmit_verify_url (local dev)', () => {
    expect(() =>
      loadConfig(writeConfig({ agentadmit_verify_url: 'http://127.0.0.1:4000/api/v1/verify' })),
    ).not.toThrow();
  });
});
