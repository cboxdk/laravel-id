<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\Identity\Models\Session;
use Cbox\Id\OAuthServer\Enums\AuthenticationContextClass;
use Cbox\Id\OAuthServer\Enums\AuthenticationShortfall;
use Cbox\Id\OAuthServer\Exceptions\InvalidAuthenticationRequirement;
use Cbox\Id\OAuthServer\Support\BearerChallenge;
use Illuminate\Http\Request;
use InvalidArgumentException;

/**
 * How recent and how strong a login must be: `max_age` and `acr_values`, the two
 * parameters RFC 9470 carries from a resource server's challenge, through the client, to
 * the authorization request — and the one place both ends evaluate them.
 *
 * BOTH SIDES OF STEP-UP, ONE RULE.
 *
 *  - A RESOURCE SERVER states what it needs (`AuthenticationRequirement::of(Aal2, 300)`),
 *    checks a validated token against it with {@see assessToken()}, and on a shortfall
 *    answers 401 with {@see challenge()} — `insufficient_user_authentication` naming the
 *    same `acr_values` and `max_age`.
 *  - The HOST'S `/authorize` reads the parameters with {@see fromAuthorizationRequest()}
 *    (refusing a malformed `max_age` as `invalid_request`) and asks
 *    {@see assessSession()} whether the person's session already meets them, or must
 *    sign in again ({@see AuthenticationAssessment::requiresReauthentication()}) or add a
 *    factor ({@see AuthenticationAssessment::requiresStepUp()}).
 *
 * The two evaluations share the class ordering, the leeway and the fail-closed rules
 * below. If they did not, a token the authorization server considered fresh enough could
 * be refused by the resource that asked for it, and the client would loop between the two.
 *
 * WHICH `acr_values` COUNT. The strongest class this server asserts
 * ({@see AuthenticationContextClass::fromRequest()}, the rule discovery's
 * `acr_values_supported` advertises), and a higher class satisfies a lower one — an aal2
 * login meets an aal1 requirement. Values this server does not assert are ignored, as
 * OIDC Core §3.1.2.1 treats `acr_values` (a list of acceptable classes, which may name
 * another provider's); a requirement naming only foreign values therefore demands no
 * class at all. A resource server should name a class from `acr_values_supported`.
 *
 * WHAT IT DOES NOT READ: `prompt=login`. That asks for a sign-in during THIS request,
 * which only the host's flow knows whether it performed; it is not a property of a
 * session that can be checked afterwards.
 */
readonly class AuthenticationRequirement
{
    /**
     * Slack on the `max_age` comparison, in seconds.
     *
     * Covers the redirect between a re-authentication being recorded and the resumed
     * authorization request reading it, the gap until the resulting token reaches the
     * resource server, and modest clock skew. Without it `max_age=0` — the case the
     * parameter exists for — is unsatisfiable: every session was created strictly before
     * the instant it is checked, including the one created a moment ago.
     */
    public const DEFAULT_MAX_AGE_LEEWAY_SECONDS = 60;

    /**
     * @param  list<string>  $acrValues  requested classes, in order of preference
     * @param  int|null  $maxAge  the allowable elapsed time since authentication, in seconds
     *
     * @throws InvalidArgumentException for a negative `max_age` or a blank or
     *                                  whitespace-bearing `acr_values` entry
     */
    public function __construct(
        public array $acrValues = [],
        public ?int $maxAge = null,
    ) {
        if ($maxAge !== null && $maxAge < 0) {
            throw new InvalidArgumentException('max_age must be a non-negative integer.');
        }

        foreach ($acrValues as $value) {
            if ($value === '' || preg_match('/\s/', $value) === 1) {
                throw new InvalidArgumentException('An acr_values entry must be a non-empty string without whitespace.');
            }
        }
    }

    /** No requirement: every authentication meets it. */
    public static function none(): self
    {
        return new self;
    }

    /**
     * A resource server's requirement: at least this class, no older than this.
     */
    public static function of(AuthenticationContextClass|string|null $acr = null, ?int $maxAge = null): self
    {
        $value = $acr instanceof AuthenticationContextClass ? $acr->value : $acr;

        return new self($value === null ? [] : [$value], $maxAge);
    }

    /**
     * Read `acr_values` and `max_age` off an authorization request: the query/form of
     * `GET /authorize`, or the consumed PAR payload (RFC 9126 — the pushed parameters ARE
     * the request, so pass that array rather than the front-channel query).
     *
     * An absent or empty parameter is no requirement. A `max_age` that is not a
     * non-negative integer, or an `acr_values` that is not a string, is
     * {@see InvalidAuthenticationRequirement} — `invalid_request` to the client.
     *
     * @param  Request|array<array-key, mixed>  $request
     *
     * @throws InvalidAuthenticationRequirement
     */
    public static function fromAuthorizationRequest(Request|array $request): self
    {
        $maxAge = $request instanceof Request ? $request->input('max_age') : ($request['max_age'] ?? null);
        $acrValues = $request instanceof Request ? $request->input('acr_values') : ($request['acr_values'] ?? null);

        return new self(self::parseAcrValues($acrValues), self::parseMaxAge($maxAge));
    }

    public function isEmpty(): bool
    {
        return $this->maxAge === null && $this->requiredClass() === null;
    }

    /**
     * The class an authentication must reach: the strongest named that this server
     * asserts, or null when none is.
     */
    public function requiredClass(): ?AuthenticationContextClass
    {
        return AuthenticationContextClass::fromRequest(implode(' ', $this->acrValues));
    }

    /**
     * The general evaluation: an authentication that achieved `$acr` at `$authTime`.
     *
     * Fails closed on missing facts. With a `max_age`, an unknown `auth_time` is
     * {@see AuthenticationShortfall::TooOld}; with a required class, an unknown or
     * unrecognised `acr` is {@see AuthenticationShortfall::ContextNotMet}.
     *
     * @param  int|null  $now  unix time to measure against; defaults to the application clock
     */
    public function assess(?string $acr, ?int $authTime, ?int $now = null, int $leeway = self::DEFAULT_MAX_AGE_LEEWAY_SECONDS): AuthenticationAssessment
    {
        $shortfalls = [];

        if ($this->maxAge !== null) {
            // `age > maxAge + leeway`, compared as an AGE: see DEFAULT_MAX_AGE_LEEWAY_SECONDS.
            // now(), not time(): one clock for the application, and the one a test can move.
            $now ??= now()->getTimestamp();

            if ($authTime === null || ($now - $authTime) > ($this->maxAge + max(0, $leeway))) {
                $shortfalls[] = AuthenticationShortfall::TooOld;
            }
        }

        $required = $this->requiredClass();

        if ($required !== null) {
            $achieved = $acr === null ? null : AuthenticationContextClass::tryFrom($acr);

            if ($achieved === null || ! self::reaches($achieved, $required)) {
                $shortfalls[] = AuthenticationShortfall::ContextNotMet;
            }
        }

        return new AuthenticationAssessment($this, $shortfalls, $acr, $authTime);
    }

    /**
     * Authorization-server side: does the person's current sign-in session meet this?
     *
     * `auth_time` is the session's `created_at` (the moment it was authenticated) and the
     * achieved class is derived from its `amr` — exactly what the authorization code is
     * then issued with, so the token's `acr` and `auth_time` are the ones assessed here.
     * No session meets nothing but the empty requirement.
     */
    public function assessSession(?Session $session, ?int $now = null, int $leeway = self::DEFAULT_MAX_AGE_LEEWAY_SECONDS): AuthenticationAssessment
    {
        if ($session === null) {
            return $this->assess(null, null, $now, $leeway);
        }

        // array_values(): a JSON column is not guaranteed to rehydrate as a list.
        $amr = array_values($session->amr);

        return $this->assess(
            AuthenticationContextClass::forAmr($amr)->value,
            $session->created_at?->getTimestamp(),
            $now,
            $leeway,
        );
    }

    /**
     * Resource-server side: does a validated access token's login meet this?
     *
     * Reads the RFC 9470 §6 `acr` and `auth_time` from the token's claims (RFC 9068) or
     * an introspection response (RFC 7662) — {@see Introspection} carries both. The caller
     * has already decided the token is active and meant for it; this answers only whether
     * the authentication behind it is recent and strong enough.
     */
    public function assessToken(Introspection $token, ?int $now = null, int $leeway = self::DEFAULT_MAX_AGE_LEEWAY_SECONDS): AuthenticationAssessment
    {
        return $this->assess($token->acr(), $token->authTime(), $now, $leeway);
    }

    /**
     * The RFC 9470 §3 challenge for this requirement — send with status 401.
     *
     * Names the WHOLE requirement, not only the part that failed: the client turns the
     * challenge into its next authorization request, and a token that comes back fresh
     * but at the wrong class (or the reverse) would be refused again.
     */
    public function challenge(?BearerChallenge $base = null, ?string $description = null): BearerChallenge
    {
        return ($base ?? new BearerChallenge)->insufficientUserAuthentication($this->acrValues, $this->maxAge, $description);
    }

    /** A higher class satisfies a lower one: aal2 meets aal1. */
    private static function reaches(AuthenticationContextClass $achieved, AuthenticationContextClass $required): bool
    {
        return $required === AuthenticationContextClass::Aal1 || $achieved === $required;
    }

    /**
     * @return list<string>
     */
    private static function parseAcrValues(mixed $value): array
    {
        if ($value === null || $value === '') {
            return [];
        }

        if (! is_string($value)) {
            throw InvalidAuthenticationRequirement::malformedAcrValues();
        }

        $values = preg_split('/\s+/', trim($value), -1, PREG_SPLIT_NO_EMPTY);

        return $values === false ? [] : array_values(array_unique($values));
    }

    /**
     * OIDC Core §3.1.2.1 / RFC 9470 §3: a non-negative integer number of seconds. Digits
     * only — no sign, no fraction, no exponent — and within the platform integer, so
     * `max_age=99999999999999999999` is refused rather than silently saturated.
     */
    private static function parseMaxAge(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_int($value)) {
            return $value >= 0 ? $value : throw InvalidAuthenticationRequirement::malformedMaxAge();
        }

        if (! is_string($value) || ! ctype_digit($value)) {
            throw InvalidAuthenticationRequirement::malformedMaxAge();
        }

        // Leading zeros stripped first: "007" is seven seconds, though filter_var would read
        // it as an octal literal and refuse it.
        $digits = ltrim($value, '0');
        $parsed = filter_var($digits === '' ? '0' : $digits, FILTER_VALIDATE_INT);

        return is_int($parsed) ? $parsed : throw InvalidAuthenticationRequirement::malformedMaxAge();
    }
}
