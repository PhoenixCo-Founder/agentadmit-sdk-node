/**
 * agentadmit/ownerLink.ts
 * Owner link for a pending confirm-each-time action (1.15.0).
 *
 * When a scope needs a fresh human confirmation and the user has no passkey
 * on file for the app yet, the link the agent holds cannot be used alone.
 * The app's backend asks the hosted service for an owner link for its own
 * signed-in user and sends that user to `owner_session_url`. On that page the
 * user creates a passkey and confirms the action; on a computer the page can
 * show a QR code to continue on the user's phone.
 *
 * Two rules:
 *   1. Call `createOwnerLink()` only from a route your signed-in human uses,
 *      passing that user's id.
 *   2. Never return `owner_session_url` to an agent. Whoever opens it can
 *      create the passkey that confirms the action.
 *
 * This module is not mounted on the SDK router on purpose: the router serves
 * agent-facing routes.
 */

import { getConfig } from './config';

/** The hosted answer to an owner-link request. */
export interface OwnerLink {
  action_session_id: string;
  /**
   * The page to send the signed-in user to. Single-use token in the URL
   * fragment: never log it, never hand it to an agent.
   */
  owner_session_url: string;
  /** `true`: the user creates a passkey on that page first. `false`: one is on file and the URL is the ordinary confirmation page. */
  enrollment_required: boolean;
  /** Why a passkey is needed (`no_passkey` or `no_eligible_authenticator`); present only when `enrollment_required` is true. */
  enrollment_reason?: string;
  expires_at: string;
}

/**
 * An error from the owner-link call. `status` is the HTTP status the hosted
 * service answered, `code` its `error` code when there is one (null for a
 * malformed success body).
 * The message never carries the owner link.
 */
export interface OwnerLinkError extends Error {
  status: number;
  code: string | null;
  data: Record<string, unknown>;
}

const ACTION_SESSION_ID_MIN = 20;
const APP_USER_ID_MAX = 255;

function ownerLinkError(message: string, status: number, code: string | null, data: Record<string, unknown>): OwnerLinkError {
  const err = new Error(message) as OwnerLinkError;
  err.status = status;
  err.code = code;
  err.data = data;
  return err;
}

/**
 * Open a pending confirmation for your own signed-in user.
 *
 * `POST /api/v1/action-sessions/{actionSessionId}/owner-link` with the app's
 * API key and `{ app_user_id }`. `actionSessionId` is the
 * `confirmation.action_session_id` from the `confirmation_required` refusal;
 * `appUserId` is the id of the user your backend has signed in, and it must
 * be the user the confirmation is for.
 *
 * Call it only from a route your signed-in human uses; never return
 * `owner_session_url` to an agent.
 *
 * @throws TypeError on a bad argument, before any network call.
 * @throws OwnerLinkError on any non-2xx answer (no retry) or a malformed 2xx body.
 */
export async function createOwnerLink(actionSessionId: string, appUserId: string): Promise<OwnerLink> {
  if (typeof actionSessionId !== 'string' || !actionSessionId.startsWith('asess_') || actionSessionId.length < ACTION_SESSION_ID_MIN) {
    throw new TypeError('actionSessionId must be the action_session_id from the confirmation block (asess_...)');
  }
  if (typeof appUserId !== 'string' || appUserId.length === 0 || appUserId.length > APP_USER_ID_MAX) {
    throw new TypeError(`appUserId must be a non-empty string of at most ${APP_USER_ID_MAX} characters`);
  }

  const config = getConfig();
  const url = `${config.agentadmit_api_url.replace(/\/$/, '')}/api/v1/action-sessions/${encodeURIComponent(actionSessionId)}/owner-link`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.api_key}`,
      'Content-Type': 'application/json',
      'X-App-Id': config.app_id,
    },
    body: JSON.stringify({ app_user_id: appUserId }),
  });

  const data = (await resp.json().catch(() => ({}))) as Record<string, unknown>;
  const body = data && typeof data === 'object' && !Array.isArray(data) ? data : {};

  if (!resp.ok) {
    const code = typeof body.error === 'string' ? body.error : null;
    throw ownerLinkError(`Owner link request failed: HTTP ${resp.status}${code ? ` ${code}` : ''}`, resp.status, code, body);
  }

  if (
    typeof body.owner_session_url !== 'string' ||
    typeof body.enrollment_required !== 'boolean' ||
    typeof body.action_session_id !== 'string' ||
    typeof body.expires_at !== 'string'
  ) {
    // The body is not attached: it may hold a partial owner link.
    throw ownerLinkError('Malformed owner link response from the authorization service', resp.status, null, {});
  }

  return {
    action_session_id: body.action_session_id,
    owner_session_url: body.owner_session_url,
    enrollment_required: body.enrollment_required,
    ...(body.enrollment_required && typeof body.enrollment_reason === 'string'
      ? { enrollment_reason: body.enrollment_reason }
      : {}),
    expires_at: body.expires_at,
  };
}
