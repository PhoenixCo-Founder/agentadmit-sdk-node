/**
 * App-attested presence: a ceremony fact your app attests at token issuance.
 *
 * Return an instance from the `requireTokenMintPresence` hook AFTER verifying
 * and consuming your own fresh, purpose-bound WebAuthn/passkey attestation.
 * The SDK forwards it to the hosted mint as
 * `presence: {verified: true, uv: true, method, verified_at}`; the hosted
 * service stores it method-prefixed `app:<method>` — the provenance marker
 * that keeps app-attested facts distinct from hosted-witnessed ceremonies.
 *
 * Honesty ceiling: this is YOUR attestation, recorded and provenance-marked,
 * not witnessed by AgentAdmit and not independently verifiable. Only
 * construct one for a ceremony that verified the user with UV (biometric or
 * PIN user verification); `verified`/`uv` are literal `true` — a ceremony
 * without UV carries no presence fact, so simply return nothing.
 *
 * `verifiedAt` must be a valid Date or an ISO-8601 string WITH an explicit
 * offset (Z or ±hh:mm) — the hosted mint rejects offset-less timestamps with
 * 400, a proven production-outage class — and recent: the hosted service
 * enforces a 10-minute freshness window with 60 seconds of future
 * clock-skew slack.
 */

const METHOD_RE = /^[a-z0-9_]+$/;
const METHOD_MAX_LENGTH = 60;
// ISO-8601 with an explicit offset. Date instances serialize via
// toISOString() (always Z) so only string inputs need this check.
const OFFSET_RE = /(?:Z|[+-]\d{2}:\d{2})$/;

export interface AppAttestedPresenceWire {
  verified: true;
  uv: true;
  method: string;
  verified_at: string;
}

export class AppAttestedPresence {
  readonly verified = true as const;
  readonly uv = true as const;
  readonly method: string;
  /** RFC 3339 timestamp with explicit offset, as sent on the wire. */
  readonly verifiedAt: string;

  constructor(opts: { method: string; verifiedAt: Date | string }) {
    const { method, verifiedAt } = opts ?? ({} as { method: string; verifiedAt: Date | string });

    if (typeof method !== 'string' || method.length < 1 || method.length > METHOD_MAX_LENGTH || !METHOD_RE.test(method)) {
      throw new Error(
        `AppAttestedPresence: method must be 1-${METHOD_MAX_LENGTH} lowercase alphanumeric/underscore characters (e.g. 'my_webauthn')`,
      );
    }

    if (verifiedAt instanceof Date) {
      if (Number.isNaN(verifiedAt.getTime())) {
        throw new Error('AppAttestedPresence: verifiedAt is an invalid Date');
      }
      this.verifiedAt = verifiedAt.toISOString();
    } else if (typeof verifiedAt === 'string') {
      if (Number.isNaN(Date.parse(verifiedAt))) {
        throw new Error('AppAttestedPresence: verifiedAt does not parse as a timestamp');
      }
      if (!OFFSET_RE.test(verifiedAt)) {
        // An offset-less timestamp serializes ambiguously and the hosted
        // mint rejects it with 400 — fail here, where the fix is obvious.
        throw new Error(
          'AppAttestedPresence: verifiedAt must carry an explicit offset (Z or ±hh:mm); pass a Date to serialize safely',
        );
      }
      this.verifiedAt = verifiedAt;
    } else {
      throw new Error('AppAttestedPresence: verifiedAt must be a Date or an ISO-8601 string with offset');
    }

    this.method = method;
  }

  /** The exact JSON object forwarded to the hosted mint. */
  toWire(): AppAttestedPresenceWire {
    return {
      verified: true,
      uv: true,
      method: this.method,
      verified_at: this.verifiedAt,
    };
  }
}
