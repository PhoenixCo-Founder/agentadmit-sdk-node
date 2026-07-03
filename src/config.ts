/**
 * agentadmit/config.ts
 * Configuration loader for AgentAdmit Node.js SDK.
 *
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */

import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

export interface ScopeDefinition {
  name: string;
  description: string;
  category?: string;
  role?: string;
}

export interface DurationOption {
  label: string;
  seconds: number | null; // null = "until revoked"
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

const DEFAULT_CONFIG: Partial<AgentAdmitConfig> = {
  app_name: 'My App',
  app_id: '',
  api_key: '',
  api_base_url: 'http://localhost:3000',
  agentadmit_api_url: 'https://api.agentadmit.com',
  agentadmit_verify_url: 'https://api.agentadmit.com/api/v1/verify',
  token_prefix_connection: 'ag_ct_',
  token_prefix_access: 'ag_at_',
  algorithm: 'RS256',
  audience: 'agentadmit',
  connection_token_ttl: 900,
  scopes: [],
  durations: [
    { label: '1 Hour', seconds: 3600 },
    { label: '24 Hours', seconds: 86400 },
    { label: '7 Days', seconds: 604800 },
    { label: '30 Days', seconds: 2592000 },
    { label: 'Until I Revoke', seconds: null },
  ],
  tiers: [
    { name: 'trial', connections_limit: 3, hard_cap: true },
    { name: 'standard', connections_limit: 100, api_calls_monthly: 2000000, hard_cap: false },
  ],
  default_tier: 'standard',
  storage: {
    backend: 'mongodb',
    uri: 'mongodb://localhost:27017',
    database: 'agentadmit',
    connections_collection: 'agentadmit_connections',
    audit_log_collection: 'agentadmit_audit_log',
    tokens_collection: 'agentadmit_tokens',
  },
  route_prefix: '/agentadmit',
  discovery_path: '/.well-known/agentadmit',
  user_lookup_field: 'user_id',
  max_retries: 3,
};

let _config: AgentAdmitConfig | null = null;

/**
 * Localhost hostnames that are permitted to use http:// (local dev/testing only).
 */
const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Validate that a URL uses https://, with an exception for http:// when the
 * host is a localhost address (for local development and testing).
 *
 * Throws a configuration error with a clear message on violation.
 */
export function validateUrlScheme(url: string, fieldName: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Configuration error: ${fieldName} is not a valid URL: ${url}`);
  }

  if (parsed.protocol === 'https:') {
    return; // always allowed
  }

  if (parsed.protocol === 'http:' && LOCALHOST_HOSTS.has(parsed.hostname)) {
    return; // http:// localhost exception for local dev
  }

  throw new Error(
    `Configuration error: ${fieldName} must use https:// (got ${parsed.protocol}//${parsed.host}). ` +
    `http:// is only permitted for localhost, 127.0.0.1, or [::1].`,
  );
}

export function loadConfig(configPath: string = 'agentadmit.yaml'): AgentAdmitConfig {
  let resolvedPath = configPath;

  if (!fs.existsSync(resolvedPath)) {
    const envPath = process.env.AGENTADMIT_CONFIG;
    if (envPath && fs.existsSync(envPath)) {
      resolvedPath = envPath;
    } else {
      throw new Error(
        `Config file not found: ${configPath}. Create an agentadmit.yaml with your app_id, api_key, and scopes.`
      );
    }
  }

  const raw = yaml.load(fs.readFileSync(resolvedPath, 'utf-8')) as Record<string, any> || {};
  _config = { ...DEFAULT_CONFIG, ...raw } as AgentAdmitConfig;

  // Validate the key prefix without ever echoing the key itself.
  if (_config.api_key && !/^aa_(test|live)_/.test(_config.api_key)) {
    throw new Error("Invalid api_key: must start with 'aa_test_' or 'aa_live_'");
  }

  // Enforce https:// on all remote URLs (localhost http:// is allowed for dev).
  validateUrlScheme(_config.agentadmit_api_url, 'agentadmit_api_url');
  validateUrlScheme(_config.agentadmit_verify_url, 'agentadmit_verify_url');

  console.log(`[AgentAdmit] Config loaded: ${resolvedPath} (${_config.scopes.length} scopes)`);
  return _config;
}

export function getConfig(): AgentAdmitConfig {
  if (!_config) {
    throw new Error('AgentAdmit config not loaded. Call loadConfig() first.');
  }
  return _config;
}

export function getScopeMetadata(): ScopeDefinition[] {
  return getConfig().scopes;
}

export function getDurationOptions(): DurationOption[] {
  return getConfig().durations;
}

export function getTierLimits(tierName: string): TierDefinition | undefined {
  const config = getConfig();
  return config.tiers.find(t => t.name === tierName) || config.tiers.find(t => t.name === config.default_tier);
}
