/**
 * agentadmit/errors.ts
 * Custom error types for the AgentAdmit Node.js SDK.
 */

/**
 * Thrown when the AgentAdmit introspection endpoint returns HTTP 429
 * and all retry attempts (with exponential backoff) have been exhausted.
 *
 * @example
 * ```ts
 * import { validateAgentToken, RateLimitError } from '@agentadmit/sdk';
 *
 * try {
 *   await validateAgentToken(token);
 * } catch (err) {
 *   if (err instanceof RateLimitError) {
 *     res.status(429).json({
 *       error: 'rate_limited',
 *       retry_after: err.retryAfter,
 *     });
 *   }
 * }
 * ```
 */
export class RateLimitError extends Error {
  /** Seconds to wait before retrying (from Retry-After header), or null. */
  readonly retryAfter: number | null;
  /** Total request limit for the current window (X-RateLimit-Limit), or null. */
  readonly limit: number | null;
  /** Requests remaining in the current window (X-RateLimit-Remaining), or null. */
  readonly remaining: number | null;
  /** Unix timestamp when the rate limit window resets (X-RateLimit-Reset), or null. */
  readonly reset: number | null;

  constructor(options: {
    message?: string;
    retryAfter?: number | null;
    limit?: number | null;
    remaining?: number | null;
    reset?: number | null;
  } = {}) {
    super(options.message ?? 'AgentAdmit rate limit exceeded. Max retries exhausted.');
    this.name = 'RateLimitError';
    this.retryAfter = options.retryAfter ?? null;
    this.limit = options.limit ?? null;
    this.remaining = options.remaining ?? null;
    this.reset = options.reset ?? null;
  }
}
