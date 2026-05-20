/**
 * agentadmit/routes.ts
 * Express router with all AgentAdmit endpoints.
 */
import { Router, Request } from 'express';
import { StorageBackend } from './storage';
interface RouterOptions {
    storage: StorageBackend;
    getCurrentUser: (req: Request) => Promise<Record<string, any> | null>;
    determineRole?: (user: Record<string, any>) => string;
    getUserTier?: (user: Record<string, any>) => string;
    validateScopes?: (scopes: string[], user: Record<string, any>) => {
        valid: boolean;
        invalid: string[];
    };
    getEndpointsForScopes?: (scopes: string[]) => Record<string, any>[];
}
export declare function createAgentAdmitRouter(options: RouterOptions): {
    wellknownRouter: Router;
    agentadmitRouter: Router;
};
export {};
