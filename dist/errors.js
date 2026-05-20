"use strict";
/**
 * agentadmit/errors.ts
 * Custom error types for the AgentAdmit Node.js SDK.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.RateLimitError = void 0;
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
class RateLimitError extends Error {
    constructor(options = {}) {
        super(options.message ?? 'AgentAdmit rate limit exceeded. Max retries exhausted.');
        this.name = 'RateLimitError';
        this.retryAfter = options.retryAfter ?? null;
        this.limit = options.limit ?? null;
        this.remaining = options.remaining ?? null;
        this.reset = options.reset ?? null;
    }
}
exports.RateLimitError = RateLimitError;
