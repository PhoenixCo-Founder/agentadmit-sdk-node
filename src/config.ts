/**
 * agentadmit/config.ts
 * Configuration loader for AgentAdmit Node.js SDK.
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
  api_base_url: string;
  private_key_path: string;
  public_key_path: string;
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
}

const DEFAULT_CONFIG: Partial<AgentAdmitConfig> = {
  app_name: 'My App',
  app_id: '',
  api_base_url: 'http://localhost:3000',
  private_key_path: 'keys/agentadmit_private.pem',
  public_key_path: 'keys/agentadmit_public.pem',
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
};

let _config: AgentAdmitConfig | null = null;

export function loadConfig(configPath: string = 'agentadmit.yaml'): AgentAdmitConfig {
  let resolvedPath = configPath;

  if (!fs.existsSync(resolvedPath)) {
    const envPath = process.env.AGENTADMIT_CONFIG;
    if (envPath && fs.existsSync(envPath)) {
      resolvedPath = envPath;
    } else {
      throw new Error(
        `Config file not found: ${configPath}. Run 'agentadmit init' to generate one.`
      );
    }
  }

  const raw = yaml.load(fs.readFileSync(resolvedPath, 'utf-8')) as Record<string, any> || {};
  _config = { ...DEFAULT_CONFIG, ...raw } as AgentAdmitConfig;

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
