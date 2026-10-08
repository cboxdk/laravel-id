<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\OAuthServer\Enums\AuthenticationShortfall;
use Cbox\Id\OAuthServer\Support\BearerChallenge;

/**
 * The answer to "does this authentication meet that requirement?" — and, when it does
 * not, what to do about it on whichever side is asking.
 *
 * An authorization endpoint reads {@see requiresReauthentication()} /
 * {@see requiresStepUp()} to decide which screen to send the person to, and
 * {@see authorizationError()} for what to tell the client when it may not interact
 * (`prompt=none`) or the person came back still short. A resource server reads
 * {@see challenge()} for its 401.
 */
readonly class AuthenticationAssessment
{
    /**
     * @param  list<AuthenticationShortfall>  $shortfalls  empty when the requirement is met
     * @param  string|null  $acr  the class the authentication achieved, as assessed
     * @param  int|null  $authTime  when it happened, as assessed
     */
    public function __construct(
        public AuthenticationRequirement $requirement,
        public array $shortfalls,
        public ?string $acr,
        public ?int $authTime,
    ) {}

    public function isSatisfied(): bool
    {
        return $this->shortfalls === [];
    }

    /** `max_age` was exceeded (or the login cannot be dated): the person must sign in again. */
    public function requiresReauthentication(): bool
    {
        return in_array(AuthenticationShortfall::TooOld, $this->shortfalls, true);
    }

    /** The requested class was not reached: the person must authenticate with a stronger method. */
    public function requiresStepUp(): bool
    {
        return in_array(AuthenticationShortfall::ContextNotMet, $this->shortfalls, true);
    }

    /**
     * The authorization-response error when the requirement cannot be met interactively,
     * or null when it is met.
     *
     * `login_required` for a login that is too old (OIDC Core §3.1.2.6) — signing in again
     * is the remedy. `unmet_authentication_requirements` for a class not reached (OpenID
     * Connect Core Error Code extension, named by RFC 9470 §5 for exactly this case). Not
     * `insufficient_user_authentication`: that is the RESOURCE SERVER's challenge (§3),
     * and a client implementing step-up branches on the two differently.
     *
     * When both fall short the age wins, matching the order the requirement is checked in:
     * a fresh sign-in may well bring the stronger factor with it.
     */
    public function authorizationError(): ?string
    {
        return match (true) {
            $this->requiresReauthentication() => 'login_required',
            $this->requiresStepUp() => 'unmet_authentication_requirements',
            default => null,
        };
    }

    /** A human-readable `error_description` for whichever side reports the shortfall. */
    public function errorDescription(): ?string
    {
        if ($this->requiresReauthentication()) {
            return 'The existing authentication is older than the requested max_age.';
        }

        if ($this->requiresStepUp()) {
            $required = $this->requirement->requiredClass();

            return 'The requested authentication context ('.($required !== null ? $required->value : implode(' ', $this->requirement->acrValues)).') was not met.';
        }

        return null;
    }

    /**
     * The resource server's RFC 9470 §3 401 challenge, built on `$base` (typically
     * `BearerChallenge::for($resource)`), or null when the requirement is met.
     */
    public function challenge(?BearerChallenge $base = null): ?BearerChallenge
    {
        return $this->isSatisfied() ? null : $this->requirement->challenge($base, $this->errorDescription());
    }
}
