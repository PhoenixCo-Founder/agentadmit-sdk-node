/**
 * @agentadmit/sdk — Node.js SDK for AgentAdmit
 * 
 * User-mediated AI agent authorization. Plug-and-play for Express and Next.js.
 */

export { loadConfig, getConfig, getScopeMetadata, getDurationOptions, getTierLimits, validateUrlScheme } from './config';
export type { AgentAdmitConfig, ScopeDefinition, DurationOption, TierDefinition, StorageConfig } from './config';

export { generateKeyPair, loadPrivateKey, loadPublicKey } from './keys';

export { StorageBackend, MongoDBStorage, MemoryStorage, createStorage } from './storage';

export {
  validateAgentToken,
  requireScope,
  requireScopeIfAgent,
  requirePresence,
  presenceVerified,
  resolveAuth,
  checkConnectionCap,
  setStorage,
  setUserVerifier,
  VERIFY_ERROR_CODES,
} from './auth';
export type { AgentContext, VerifyErrorCode, VerifyActive, VerifyInactive, PresenceInfo } from './auth';

export { checkConsent, CALLER_CLASSES } from './consent';
export type { CallerClass, ConsentVerdict, ConsentSource, CheckConsentOptions } from './consent';

export { callerConsent, classifyCaller } from './callerConsent';
export type { CallerConsentOptions, CallerConsentContext, NonAgentClass } from './callerConsent';

export {
  verifyWebhookSignature,
  isValidWebhookSignature,
  WebhookSignatureError,
  SIGNATURE_HEADER,
  DEFAULT_TOLERANCE_SECONDS,
} from './webhooks';
export type { VerifyWebhookSignatureOptions } from './webhooks';

export { createAgentAdmitRouter } from './routes';
export type { RouterOptions } from './routes';

export { AppAttestedPresence } from './appAttestedPresence';
export type { AppAttestedPresenceWire } from './appAttestedPresence';

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
