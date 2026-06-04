/**
 * agentadmit/config.ts
 * Configuration loader for AgentAdmit Node.js SDK.
 *
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */
export interface ScopeDefinition {
    name: string;
    description: string;
    category?: string;
    role?: string;
}
export interface DurationOption {
    label: string;
    seconds: number | null;
}
export interface TierDefinition {
    name: string;
    connections_limit: number;
    api_calls_monthly?: number;
    hard_cap: boolean;
    overage_per_thousand?: number;
}
export interface StorageConfig {
    backend: 'mongodb' | 'memory';
    uri?: string;
    database?: string;
    connections_collection?: string;
    audit_log_collection?: string;
    tokens_collection?: string;
}
export interface AgentAdmitConfig {
    app_name: string;
    app_id: string;
    api_key: string;
    api_base_url: string;
    agentadmit_api_url: string;
    agentadmit_verify_url: string;
    token_prefix_connection: string;
    token_prefix_access: string;
    algorithm: string;
    audience: string;
    connection_token_ttl: number;
    scopes: ScopeDefinition[];
    durations: DurationOption[];
    tiers: TierDefinition[];
    default_tier: string;
    storage: StorageConfig;
    route_prefix: string;
    discovery_path: string;
    user_lookup_field: string;
    private_key_path: string;
    public_key_path: string;
    /** Max retries on 429 before throwing RateLimitError. Default: 3. */
    max_retries: number;
}
export declare function loadConfig(configPath?: string): AgentAdmitConfig;
export declare function getConfig(): AgentAdmitConfig;
export declare function getScopeMetadata(): ScopeDefinition[];
export declare function getDurationOptions(): DurationOption[];
export declare function getTierLimits(tierName: string): TierDefinition | undefined;
