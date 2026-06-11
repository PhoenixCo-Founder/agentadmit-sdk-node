/**
 * agentadmit/auth.ts
 * Token validation, scope enforcement, and audit logging for Express.
 */
import { Request, Response, NextFunction } from 'express';
import { StorageBackend } from './storage';
export declare function setStorage(storage: StorageBackend): void;
export declare function setUserVerifier(fn: (token: string) => string | Promise<string>): void;
export interface AgentContext {
    auth_type: 'agent' | 'user';
    user: Record<string, any>;
    connection: Record<string, any> | null;
    scopes: string[];
}
/**
 * Error codes the hosted /api/v1/verify endpoint returns with HTTP 200 and
 * `active: false`. Unknown codes pass through as plain strings.
 */
export declare const VERIFY_ERROR_CODES: readonly ["invalid_token", "token_expired", "token_revoked", "connection_revoked", "connection_expired", "environment_mismatch", "insufficient_scope"];
export type VerifyErrorCode = (typeof VERIFY_ERROR_CODES)[number];
/** Successful introspection result from /api/v1/verify. */
export interface VerifyActive {
    active: true;
    sub?: string;
    user_id?: string;
    connection_id?: string;
    scopes?: string[];
    role?: string;
    app_id?: string;
    jti?: string;
    exp?: number;
}
/** Failed (but non-fatal) introspection result — HTTP 200, active: false. */
export interface VerifyInactive {
    active: false;
    error?: VerifyErrorCode | (string & {});
}
/**
 * Validate an ag_at_ token and return the agent context.
 */
export declare function validateAgentToken(token: string): Promise<Omit<AgentContext, 'auth_type'>>;
/**
 * Express middleware: require a specific scope (agent-only).
 */
export declare function requireScope(scope: string): (req: Request, res: Response, next: NextFunction) => Promise<Response<any, Record<string, any>> | undefined>;
/**
 * Express middleware: enforce scope only if caller is an agent.
 */
export declare function requireScopeIfAgent(scope: string): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
/**
 * Express middleware: resolve user or agent from token.
 */
export declare function resolveAuth(): (req: Request, res: Response, next: NextFunction) => Promise<void | Response<any, Record<string, any>>>;
/**
 * Check connection cap for tier enforcement.
 */
export declare function checkConnectionCap(userId: string, tier: string): Promise<void>;
