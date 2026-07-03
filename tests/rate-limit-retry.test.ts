/**
 * Regression tests for 429 retry handling in validateAgentToken.
 *
 * A server-supplied Retry-After header is untrusted input: a compromised or
 * misconfigured endpoint could send `Retry-After: 3600` and pin the caller's
 * request thread for an hour. Every wait must be capped at 30 seconds, and
 * the cumulative wait across retries of one verify call must be capped at
 * 120 seconds.
 */

import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { loadConfig } from '../src/config';
import { validateAgentToken } from '../src/auth';
import { RateLimitError } from '../src/errors';

function writeTestConfig(extra: string[] = []): string {
  const dir = mkdtempSync(join(tmpdir(), 'aa-node-retry-test-'));
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
    ...extra,
  ].join('\n'));
  return path;
}

function rateLimited429(retryAfterSeconds: number): Response {
  return new Response(JSON.stringify({ error: 'rate_limited' }), {
    status: 429,
    headers: {
      'Content-Type': 'application/json',
      'Retry-After': String(retryAfterSeconds),
    },
  });
}

describe('429 retry: Retry-After cap and total wait budget', () => {
  const realFetch = global.fetch;
  let setTimeoutSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.useFakeTimers();
    // Deterministic jitter: always 250 ms.
    jest.spyOn(Math, 'random').mockReturnValue(0.5);
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    setTimeoutSpy = jest.spyOn(global, 'setTimeout');
  });

  afterEach(() => {
    global.fetch = realFetch;
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  /** Let pending promise callbacks run (fake timers don't advance microtasks). */
  async function flushMicrotasks(): Promise<void> {
    for (let i = 0; i < 10; i++) await Promise.resolve();
  }

  /** Drain the retry loop: advance fake time until the promise settles. */
  async function settle(promise: Promise<unknown>): Promise<Error> {
    let settled: Error | null = null;
    promise.catch((err) => { settled = err; });
    // Generous upper bound on iterations; each advance covers one max wait.
    for (let i = 0; i < 20 && settled === null; i++) {
      await flushMicrotasks();
      jest.advanceTimersByTime(31_000);
      await flushMicrotasks();
    }
    if (settled === null) throw new Error('retry loop did not settle');
    return settled;
  }

  it('caps a huge server-supplied Retry-After at 30s per wait', async () => {
    loadConfig(writeTestConfig());
    global.fetch = jest.fn().mockResolvedValue(rateLimited429(3600)) as any;

    const err = await settle(validateAgentToken('ag_at_dummy_token'));

    expect(err).toBeInstanceOf(RateLimitError);
    expect(err.message).toContain('Max retries');

    // Every scheduled wait must be <= 30s + 500ms max jitter — never the
    // requested 3600s.
    const sleepDelays = setTimeoutSpy.mock.calls
      .map((call) => call[1] as number)
      .filter((ms) => typeof ms === 'number' && ms > 1000);
    expect(sleepDelays.length).toBeGreaterThan(0);
    for (const ms of sleepDelays) {
      expect(ms).toBeLessThanOrEqual(30_500);
    }
  });

  it('gives up with RateLimitError once the 120s cumulative budget is exhausted', async () => {
    // High max_retries so the budget, not the retry count, is the limiter.
    loadConfig(writeTestConfig(['max_retries: 99']));
    global.fetch = jest.fn().mockResolvedValue(rateLimited429(30)) as any;

    const err = await settle(validateAgentToken('ag_at_dummy_token'));

    expect(err).toBeInstanceOf(RateLimitError);
    expect(err.message).toContain('budget');

    // 30.25s per wait -> 3 sleeps (90.75s), then the 4th would exceed 120s.
    const sleepCount = setTimeoutSpy.mock.calls
      .filter((call) => typeof call[1] === 'number' && (call[1] as number) > 1000)
      .length;
    expect(sleepCount).toBe(3);
    expect((global.fetch as jest.Mock).mock.calls.length).toBe(4);
  });

  it('still succeeds when the server recovers within the budget', async () => {
    loadConfig(writeTestConfig());
    const okBody = {
      active: true,
      user_id: 'user_1',
      connection_id: 'conn_1',
      scopes: ['read:things'],
      agent_label: 'Test Agent',
    };
    global.fetch = jest
      .fn()
      .mockResolvedValueOnce(rateLimited429(2))
      .mockResolvedValue(
        new Response(JSON.stringify(okBody), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ) as any;

    let result: any = null;
    const promise = validateAgentToken('ag_at_dummy_token').then((r) => { result = r; });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    jest.advanceTimersByTime(3_000);
    await promise;

    expect(result.connection.connection_id).toBe('conn_1');
    expect(result.scopes).toEqual(['read:things']);
  });
});
