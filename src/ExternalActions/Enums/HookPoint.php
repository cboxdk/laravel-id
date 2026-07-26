<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Enums;

use Cbox\Id\ExternalActions\Contracts\Action;
use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Payloads\LoginPayload;
use Cbox\Id\ExternalActions\Payloads\PasswordChangePayload;
use Cbox\Id\ExternalActions\Payloads\RegistrationPayload;
use Cbox\Id\ExternalActions\Payloads\TokenMintingPayload;

/**
 * The named points where the platform pauses to consult external logic (an inline
 * hook). Each case names a moment in an operation, the typed payload the hook
 * receives, whether the hook may VETO the operation, and what an unreachable hook
 * means there ({@see failPolicy()}).
 *
 * A hook point is a PUBLIC CONTRACT: consumers switch on these cases and receiving
 * systems parse the payload. Adding a case is backward-compatible; changing a
 * payload's shape is not, which is why each payload is a typed value object
 * ({@see HookPayload}) rather than a loose array.
 *
 * See docs/extension-points/hook-points.md for the wire shapes.
 */
enum HookPoint: string
{
    // The value doubles as a config key (external_actions.hooks.<value>), so it uses
    // an underscore — a dot would collide with Laravel's config dot-notation and
    // never match a literal array key.

    /**
     * Just before an access token is signed, on every grant — including
     * `client_credentials`, which the payload distinguishes with `grant`. Enriches
     * the token's claims (reserved claims excepted) or vetoes issuance, before the
     * `jti` row is written, so a veto leaves nothing behind.
     *
     * Payload: {@see TokenMintingPayload}. Vetoes: yes. Enriches: yes (claims).
     */
    case TokenMinting = 'token_minting';

    /**
     * After authentication has SUCCEEDED and before the session row is written — the
     * host's chance to apply its own policy (device posture, geo/risk score, an
     * "employment ended" fact only its systems know) to a login the platform itself
     * has already accepted. Fires for every way a session is established: password,
     * magic link, SSO, and anything else that goes through the Identity module's
     * `SessionManager::start()`.
     *
     * Payload: {@see LoginPayload}. Vetoes: yes — no session is created.
     * Enriches: no; enrich the TOKEN at {@see self::TokenMinting}, which is where
     * claims are assembled.
     */
    case PostLogin = 'post_login';

    /**
     * Before a subject is created — the gate on self-serve signup. The canonical use
     * is a host that will admit only addresses on its own allowlist, or that runs its
     * own fraud check on the email/domain before an account exists at all.
     *
     * Payload: {@see RegistrationPayload}. Vetoes: yes — no account is created.
     * Enriches: no.
     */
    case PreRegistration = 'pre_registration';

    /**
     * Immediately after a subject has been created, in the same request, with the new
     * subject id. For hosts that need to act on a new account synchronously (seed a
     * downstream record, tell a CRM) rather than waiting on the asynchronous
     * `user.created` webhook.
     *
     * Payload: {@see RegistrationPayload}. Vetoes: NO — the account already exists
     * and this hook cannot unmake it ({@see vetoable()}). Enriches: no.
     */
    case PostRegistration = 'post_registration';

    /**
     * Before a new credential is written for a subject — every path that sets a
     * password (self-service reset, administrative assignment, invitation acceptance,
     * a user changing their own). A host enforces its own password rules here, on top
     * of the tenant's AuthPolicy.
     *
     * The password itself is NEVER sent to a hook. A rule that needs the plaintext
     * belongs in an in-process {@see Action} or behind the Identity module's
     * `BreachedPasswordCheck`, not on the wire.
     *
     * Payload: {@see PasswordChangePayload}. Vetoes: yes — the credential is not
     * written. Enriches: no.
     */
    case PrePasswordChange = 'pre_password_change';

    /**
     * After a credential has been written — the SIEM/notification signal ("this
     * account's password just changed"), delivered synchronously in the request
     * rather than through the audit stream.
     *
     * Payload: {@see PasswordChangePayload}. Vetoes: NO — the credential is already
     * written ({@see vetoable()}). Enriches: no.
     */
    case PostPasswordChange = 'post_password_change';

    /**
     * Whether a deny at this point can actually stop anything.
     *
     * A `post_*` hook runs after its operation has committed, so there is nothing left
     * to veto — and a deny that silently does nothing is worse than no deny at all.
     * The pipeline enforces this centrally: at a non-vetoable point a deny is audited
     * (so it stays visible) and then folded to an allow, rather than every call site
     * having to remember to ignore the outcome.
     */
    public function vetoable(): bool
    {
        return match ($this) {
            self::PostRegistration, self::PostPasswordChange => false,
            default => true,
        };
    }

    /**
     * What an UNREACHABLE hook means here, absent configuration. A deny is always a
     * deny; this is only about a hook that could not be consulted at all.
     */
    public function failPolicy(): FailPolicy
    {
        return match ($this) {
            // Gates. Each guards a write that is hard or impossible to undo — a signed
            // token, an account, a credential — so an unanswered gate must not read as
            // permission. The blast radius is bounded: token minting fails a grant the
            // client will retry, and registration and password changes are low-volume,
            // user-initiated operations.
            self::TokenMinting, self::PreRegistration, self::PrePasswordChange => FailPolicy::FailClosed,

            // Login is the hottest path in the product and the one with the worst
            // failure mode: fail-closed here means a customer's hook endpoint going
            // down locks every one of their users out of every application, including
            // the admin console they would use to pause the hook. The residual risk is
            // that some logins go unexamined during that outage — recoverable, where a
            // total lockout may not be. A host that would rather block than admit an
            // unexamined login sets `fail_policy.post_login => 'closed'`.
            self::PostLogin => FailPolicy::FailOpen,

            // Notifications. There is no decision to fail closed TO — the operation has
            // already committed — so an unreachable endpoint can only be skipped.
            self::PostRegistration, self::PostPasswordChange => FailPolicy::FailOpen,
        };
    }
}
