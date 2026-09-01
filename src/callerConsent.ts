/**
 * agentadmit/callerConsent.ts
 * Caller-Identity Consent middleware: the "classify caller, then gate the
 * right independent path" recipe as a single Express middleware, so an app
 * owner does not have to hand-roll it.
 *
 * One endpoint serves every caller class. On each request the middleware:
 *   1. classifies the caller from the STRUCTURE of the credential (a class the
 *      caller cannot self-select or spoof), BEFORE any consent check;
 *   2. routes to that class's ISOLATED consent path; no path reads or inherits
 *      another class's preference;
 *   3. permits or denies, and attaches the resolved context to req.agentAdmit.
 *
 *   external_agent : an `ag_at_` access token -> hosted introspection, which
 *                    returns the external-agent consent verdict inline plus the
 *                    granted scopes. Consent is evaluated BEFORE scope (a
 *                    denied class must not learn scope state or step-up
 *                    guidance). A missing or malformed verdict is resolved
 *                    through the Consent Ledger, fail-closed — absence is
 *                    never a grant.
 *   in_app_ai      : your application's own server-side AI code path -> the
 *                    Consent Ledger `/consent/check` for the in-app-AI class.
 *   human_session  : your application's own permission model (sharing, roles,
 *                    grants). Deferred to your existing authorization by
 *                    default; opt in to a stored human-session consent switch
 *                    with `gateHuman: true`.
 *
 * The three decisions are independent: granting one never grants another.
 *
 * SECURITY: this is a consent gate, not an authenticator. It classifies the
 * caller and enforces the per-class CONSENT decision; it does not by itself
 * authenticate a human session. Run it AFTER your own authentication. On the
 * human_session path it defers to your application's permission model and
 * calls next() without re-authenticating, so a request carrying no agent
 * token reaches your handler as a human session for your own authorization
 * to judge. The external_agent path is always authenticated (hosted token
 * introspection); the in_app_ai path always evaluates the ledger.
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { getConfig } from './config';
import { VerifyRefusedError } from './errors';
import { requestTelemetry, validateAgentToken } from './auth';
import { checkConsent, CallerClass } from './consent';

/** The two token-less classes an app distinguishes from its own credentials. */
export type NonAgentClass = 'human_session' | 'in_app_ai';

export interface CallerConsentOptions {
  /**
   * Resolve the data owner (your app's user id) whose resource is being
   * accessed. Required for the in_app_ai path, and for human_session when
   * `gateHuman` is set. For external_agent the owner is taken from the token,
   * so this is not consulted there.
   */
  resolveDataOwnerId?: (req: Request, callerClass: CallerClass) => string | Promise<string>;

  /**
   * Distinguish your application's own internal-AI code path from an ordinary
   * human session, deterministically, from the STRUCTURE of the credential or
   * request context (for example an internal service token, never a value the
   * caller can set). Defaults to treating non-agent callers as human sessions.
   */
  classifyNonAgent?: (req: Request) => NonAgentClass;

  /** For the external_agent path, require this scope (403 if not granted). */
  requiredScope?: string;

  /** Optional finer-than-class consent group for the ledger check. */
  scopeGroup?: string;

  /**
   * Also gate the human_session class against a stored human-session consent
   * switch. Off by default: the human path belongs to your own permission
   * model, and this middleware defers to it unless you opt in.
   */
  gateHuman?: boolean;
}

/** Context the middleware attaches to `req.agentAdmit`. */
export interface CallerConsentContext {
  auth_type: 'agent' | 'in_app_ai' | 'user';
  caller_class: CallerClass;
  [key: string]: unknown;
}

function getBearerToken(req: Request): string | null {
  const auth = req.headers.authorization || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

/**
 * Classify the caller from credential structure, before any consent check.
 * An `ag_at_` access token is an external agent; anything else is resolved by
 * `classifyNonAgent` (default: human_session). The class is derived, never
 * self-selected by the caller.
 */
export function classifyCaller(req: Request, options: CallerConsentOptions = {}): CallerClass {
  const token = getBearerToken(req);
  const config = getConfig();
  if (token && token.startsWith(config.token_prefix_access)) {
    return 'external_agent';
  }
  return options.classifyNonAgent ? options.classifyNonAgent(req) : 'human_session';
}

async function resolveOwner(
  options: CallerConsentOptions,
  req: Request,
  callerClass: CallerClass,
): Promise<string | null> {
  if (!options.resolveDataOwnerId) return null;
  const owner = await options.resolveDataOwnerId(req, callerClass);
  return owner || null;
}

/**
 * Express middleware enforcing caller-identity consent at a single endpoint.
 *
 * @example
 * app.get('/api/records/:id',
 *   callerConsent({
 *     classifyNonAgent: (req) =>
 *       req.headers['x-internal-ai'] === INTERNAL_AI_SECRET ? 'in_app_ai' : 'human_session',
 *     resolveDataOwnerId: (req) => req.params.id,
 *     requiredScope: 'read:records',
 *   }),
 *   (req, res) => res.json(getRecord(req.params.id)),
 * );
 */
export function callerConsent(options: CallerConsentOptions = {}): RequestHandler {
  return async (req: Request, res: Response, next: NextFunction) => {
    const callerClass = classifyCaller(req, options);

    // ── external_agent: hosted introspection carries the verdict + scopes ──
    if (callerClass === 'external_agent') {
      const token = getBearerToken(req) as string;
      let ctx;
      try {
        // Declare the exact exercised scope in the same hosted round trip,
        // with consent_first guaranteeing that a denied caller class cannot
        // learn scope state before this middleware returns its consent 403.
        const telemetry = requestTelemetry(req, options.requiredScope) ?? {};
        telemetry.consent_first = true;
        ctx = await validateAgentToken(token, telemetry);
      } catch (err: any) {
        if (err instanceof VerifyRefusedError) {
          return res.status(403).json(err.payload);
        }
        return res.status(401).json({ error: 'invalid_token', error_description: err.message });
      }

      // Consent first (Patent FIG. 3: the class consent decision precedes
      // scope evaluation). Checking scope first leaked granted-scope state and
      // step-up guidance to callers whose class the owner had denied. The
      // hosted service omits the verdict when its consent read fails (designed
      // degraded mode), so an absent or malformed verdict is resolved through
      // the Consent Ledger — never treated as a grant.
      let consent = ctx.consent;
      if (!consent || typeof consent.granted !== 'boolean') {
        const config = getConfig();
        const owner = (ctx.user as any)?.[config.user_lookup_field];
        if (!owner || typeof owner !== 'string') {
          return res.status(503).json({
            error: 'consent_unavailable',
            error_description: 'introspection carried no consent verdict and no resolvable data owner',
          });
        }
        try {
          consent = await checkConsent({ appUserId: owner, callerClass: 'external_agent', scopeGroup: options.scopeGroup });
        } catch (err: any) {
          return res.status(503).json({ error: 'consent_unavailable', error_description: err.message });
        }
      }
      if (consent.granted !== true) {
        return res.status(403).json({
          error: 'consent_not_granted',
          caller_class: 'external_agent',
          source: consent.source,
        });
      }

      if (options.requiredScope && !ctx.scopes.includes(options.requiredScope)) {
        return res.status(403).json({
          error: 'insufficient_scope',
          required_scope: options.requiredScope,
          granted_scopes: ctx.scopes,
        });
      }

      (req as any).agentAdmit = { auth_type: 'agent', caller_class: 'external_agent', ...ctx, consent };
      return next();
    }

    // ── in_app_ai: your own AI code path, gated on the ledger ──────────────
    if (callerClass === 'in_app_ai') {
      const owner = await resolveOwner(options, req, 'in_app_ai');
      if (!owner) {
        return res.status(500).json({
          error: 'server_error',
          error_description: 'resolveDataOwnerId is required for the in_app_ai path',
        });
      }
      let verdict;
      try {
        verdict = await checkConsent({ appUserId: owner, callerClass: 'in_app_ai', scopeGroup: options.scopeGroup });
      } catch (err: any) {
        // Fail closed: an unreachable or erroring ledger denies, never allows.
        return res.status(503).json({ error: 'consent_unavailable', error_description: err.message });
      }
      if (!verdict.granted) {
        return res.status(403).json({ error: 'consent_not_granted', caller_class: 'in_app_ai', source: verdict.source });
      }
      (req as any).agentAdmit = { auth_type: 'in_app_ai', caller_class: 'in_app_ai', consent: verdict };
      return next();
    }

    // ── human_session: your own permission model (Branch A) ────────────────
    if (options.gateHuman) {
      const owner = await resolveOwner(options, req, 'human_session');
      if (!owner) {
        return res.status(500).json({
          error: 'server_error',
          error_description: 'resolveDataOwnerId is required when gateHuman is set',
        });
      }
      let verdict;
      try {
        verdict = await checkConsent({ appUserId: owner, callerClass: 'human_session', scopeGroup: options.scopeGroup });
      } catch (err: any) {
        return res.status(503).json({ error: 'consent_unavailable', error_description: err.message });
      }
      if (!verdict.granted) {
        return res.status(403).json({ error: 'consent_not_granted', caller_class: 'human_session', source: verdict.source });
      }
      (req as any).agentAdmit = { auth_type: 'user', caller_class: 'human_session', consent: verdict };
      return next();
    }

    // Default: defer the human path to the app's existing authorization.
    (req as any).agentAdmit = { auth_type: 'user', caller_class: 'human_session' };
    return next();
  };
}
