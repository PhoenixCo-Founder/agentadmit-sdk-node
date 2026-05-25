/**
 * agentadmit/alerts.ts
 * Alert configuration and event management for the AgentAdmit hosted service.
 *
 * Usage:
 *   import { configureAlerts, listAlerts, getAlertConfig } from '@agentadmit/sdk';
 *
 *   // Configure a volume spike alert
 *   const result = await configureAlerts({
 *     app_id: 'app_abc123',
 *     alert_type: 'volume_spike',
 *     enabled: true,
 *     threshold_value: 100,
 *     threshold_window_minutes: 5,
 *   });
 *
 *   // List alert events
 *   const events = await listAlerts({ app_id: 'app_abc123', alert_type: 'volume_spike' });
 *
 *   // Get current config
 *   const config = await getAlertConfig({ app_id: 'app_abc123' });
 */

import { getConfig } from './config';

/** The 6 supported alert types. */
export const ALERT_TYPES = [
  'volume_spike',
  'failed_scope_attempts',
  'burst_pattern',
  'stale_reactivation',
  'new_scope_usage',
  'revoked_connection_attempt',
] as const;

export type AlertType = typeof ALERT_TYPES[number];

export interface ConfigureAlertsOptions {
  app_id: string;
  alert_type: AlertType | string;
  connection_id?: string;
  enabled?: boolean;
  threshold_value?: number;
  threshold_window_minutes?: number;
  threshold_rate_per_minute?: number;
  stale_days?: number;
  kill_switch_enabled?: boolean;
  kill_switch_threshold_value?: number;
  kill_switch_threshold_window_minutes?: number;
}

export interface ListAlertsOptions {
  app_id: string;
  connection_id?: string;
  alert_type?: AlertType | string;
  limit?: number;
  offset?: number;
}

export interface GetAlertConfigOptions {
  app_id: string;
  connection_id?: string;
}

export interface AlertEvent {
  id?: string;
  app_id: string;
  connection_id?: string;
  alert_type: string;
  triggered_at: string;
  details?: Record<string, any>;
}

export interface AlertEventsResponse {
  events: AlertEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface AlertConfigResponse {
  app_id: string;
  app_level: Record<string, any>;
  connection_overrides: Record<string, Record<string, any>>;
  alert_types: string[];
}

/**
 * Make an authenticated request to the AgentAdmit hosted service.
 * Supports GET (with query string) and POST (with JSON body).
 */
async function callHostedService(
  method: 'GET' | 'POST',
  path: string,
  body?: Record<string, any>,
): Promise<any> {
  const config = getConfig();
  const url = `${config.agentadmit_api_url.replace(/\/$/, '')}${path}`;

  const resp = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${config.api_key}`,
      'Content-Type': 'application/json',
      'X-App-Id': config.app_id,
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });

  if (!resp.ok) {
    const errData = await resp.json().catch(() => ({}));
    const err: any = new Error(
      (errData as any).error_description || (errData as any).error || `HTTP ${resp.status}`,
    );
    err.status = resp.status;
    err.data = errData;
    throw err;
  }

  return resp.json();
}

/**
 * Configure alert thresholds for an app or connection.
 *
 * @param options - Alert configuration options.
 * @returns { ok: true, config: {...} }
 */
export async function configureAlerts(
  options: ConfigureAlertsOptions,
): Promise<{ ok: true; config: Record<string, any> }> {
  // Remove undefined values
  const body = Object.fromEntries(
    Object.entries(options).filter(([, v]) => v !== undefined),
  ) as Record<string, any>;

  return callHostedService('POST', '/api/v1/alerts', body);
}

/**
 * List alert events for an app.
 *
 * @param options - Filter and pagination options.
 * @returns { events: [...], total, limit, offset }
 */
export async function listAlerts(options: ListAlertsOptions): Promise<AlertEventsResponse> {
  const params = new URLSearchParams({ app_id: options.app_id });
  if (options.connection_id) params.set('connection_id', options.connection_id);
  if (options.alert_type) params.set('alert_type', options.alert_type);
  if (options.limit !== undefined) params.set('limit', String(options.limit));
  if (options.offset !== undefined) params.set('offset', String(options.offset));

  return callHostedService('GET', `/api/v1/alerts?${params}`);
}

/**
 * Get the current alert configuration for an app.
 *
 * @param options - App ID and optional connection ID.
 * @returns Current alert config with app-level and connection-level settings.
 */
export async function getAlertConfig(
  options: GetAlertConfigOptions,
): Promise<AlertConfigResponse> {
  const params = new URLSearchParams({ app_id: options.app_id });
  if (options.connection_id) params.set('connection_id', options.connection_id);

  return callHostedService('GET', `/api/v1/alerts/config?${params}`);
}
