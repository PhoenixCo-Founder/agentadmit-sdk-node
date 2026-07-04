/**
 * agentadmit/consent.ts
 * Consent Ledger client — hosted caller-identity consent verdicts.
 *
 * External agents get their verdict inline in the verify response
 * (VerifyActive.consent / AgentContext.consent). The two token-less caller
 * classes (human sessions and your app's own in-app AI) ask this endpoint.
 */

import { getConfig } from './config';

export const CALLER_CLASSES = ['human_session', 'in_app_ai', 'external_agent'] as const;
export type CallerClass = (typeof CALLER_CLASSES)[number];

export type ConsentSource = 'setting' | 'scope_setting' | 'app_default' | 'platform_default';

/** Consent Ledger verdict (also embedded in verify responses as `consent`). */
export interface ConsentVerdict {
  caller_class: CallerClass;
  granted: boolean;
  scope_group?: string | null;
  /** Which layer resolved it: explicit switch, app default, or platform default. */
  source: ConsentSource;
  evaluated_at: string;
}

export interface CheckConsentOptions {
  /** Your app's identifier for the data owner. */
  appUserId: string;
  callerClass: CallerClass;
  /** Optional finer-than-class consent group. */
  scopeGroup?: string;
}

async function callConsentEndpoint(path: string, body: Record<string, any>): Promise<any> {
  const config = getConfig();
  const base = ((config as any).agentadmit_api_url || 'https://api.agentadmit.com').replace(/\/$/, '');
  const resp = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${(config as any).api_key || ''}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const errData = (await resp.json().catch(() => ({}))) as Record<string, any>;
    const err: any = new Error(errData.error_description || errData.error || `HTTP ${resp.status}`);
    err.status = resp.status;
    err.data = errData;
    throw err;
  }
  return resp.json();
}

/**
 * Ask the Consent Ledger whether a caller class may act on a user's data.
 *
 * Consent is orthogonal to token revocation: on a denied verdict your app
 * returns its own 403; nothing is revoked. Every evaluation is appended to
 * the exportable consent trail.
 *
 * @example
 * const verdict = await checkConsent({ appUserId: 'user_8842', callerClass: 'in_app_ai' });
 * if (!verdict.granted) return res.status(403).json({ error: 'consent_not_granted' });
 */
export async function checkConsent(options: CheckConsentOptions): Promise<ConsentVerdict> {
  const body: Record<string, any> = {
    app_user_id: options.appUserId,
    caller_class: options.callerClass,
  };
  if (options.scopeGroup !== undefined) body.scope_group = options.scopeGroup;
  return callConsentEndpoint('/api/v1/consent/check', body) as Promise<ConsentVerdict>;
}
