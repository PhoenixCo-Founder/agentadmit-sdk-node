/**
 * @agentadmit/sdk — Node.js SDK for AgentAdmit
 * 
 * User-mediated AI agent authorization. Plug-and-play for Express and Next.js.
 */

export { loadConfig, getConfig, getScopeMetadata, getDurationOptions, getTierLimits } from './config';
export type { AgentAdmitConfig, ScopeDefinition, DurationOption, TierDefinition, StorageConfig } from './config';

export { generateKeyPair, loadPrivateKey, loadPublicKey } from './keys';

export { StorageBackend, MongoDBStorage, MemoryStorage, createStorage } from './storage';

export {
  validateAgentToken,
  requireScope,
  requireScopeIfAgent,
  resolveAuth,
  checkConnectionCap,
  setStorage,
  setUserVerifier,
} from './auth';
export type { AgentContext } from './auth';

export { createAgentAdmitRouter } from './routes';

export { RateLimitError } from './errors';

export {
  configureAlerts,
  listAlerts,
  getAlertConfig,
  ALERT_TYPES,
} from './alerts';
export type {
  AlertType,
  ConfigureAlertsOptions,
  ListAlertsOptions,
  GetAlertConfigOptions,
  AlertEvent,
  AlertEventsResponse,
  AlertConfigResponse,
} from './alerts';
