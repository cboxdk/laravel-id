<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\ValueObjects;

use Cbox\Id\Kernel\Authorization\Support\Scopes;

/**
 * RFC 7662-style introspection result.
 */
readonly class Introspection
{
    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    private function __construct(
        public bool $active,
        public ?string $subject,
        public ?string $clientId,
        public array $scopes,
        public array $claims,
    ) {}

    /**
     * @param  list<string>  $scopes
     * @param  array<string, mixed>  $claims
     */
    public static function active(?string $subject, ?string $clientId, array $scopes, array $claims): self
    {
        return new self(true, $subject, $clientId, $scopes, $claims);
    }

    public static function inactive(): self
    {
        return new self(false, null, null, [], []);
    }

    /** Whether the token holds $scope, under any of its names ({@see Scopes}). */
    public function hasScope(string $scope): bool
    {
        return Scopes::satisfies($this->scopes, $scope);
    }

    /**
     * Whether this token was minted for $expected — its `aud` (RFC 7519) names that
     * audience. A token with no `aud` is treated as first-party (nothing to enforce);
     * a token audienced for a *different* resource (an RFC 8707 resource indicator)
     * does not match, so a first-party endpoint can refuse a token minted for someone
     * else's API.
     */
    public function isAudience(string $expected): bool
    {
        $aud = $this->claims['aud'] ?? null;

        if ($aud === null || $aud === '') {
            return true;
        }

        if (is_string($aud)) {
            return hash_equals($aud, $expected);
        }

        if (is_array($aud)) {
            foreach ($aud as $entry) {
                if (is_string($entry) && hash_equals($entry, $expected)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * RFC 9470 §6: the authentication context class the login behind this token achieved
     * (`acr`), or null when the token carries none — a `client_credentials` token, or a
     * grant that recorded no authentication methods.
     */
    public function acr(): ?string
    {
        $acr = $this->claims['acr'] ?? null;

        return is_string($acr) && $acr !== '' ? $acr : null;
    }

    /**
     * RFC 9470 §6: when the person behind this token last actively authenticated
     * (`auth_time`, unix seconds), or null when the token does not say. A refreshed token
     * carries the ORIGINAL login's time, not the refresh's.
     */
    public function authTime(): ?int
    {
        $authTime = $this->claims['auth_time'] ?? null;

        return is_int($authTime) ? $authTime : null;
    }

    /**
     * Whether this is a machine token: issued to an app for itself (`client_credentials`),
     * so the caller IS the app named by `client_id`. Active, its subject is its client id,
     * and nobody acts for anybody (no `act` claim).
     *
     * A token issued to a person through an app also carries that app's `client_id`, but it
     * acts as the person. Ask this before treating `clientId` as the caller's identity — an
     * app's own secrets, its own grants, a service-to-service question — so a person's token
     * is never mistaken for the app.
     */
    public function isMachine(): bool
    {
        return $this->active
            && $this->clientId !== null && $this->clientId !== ''
            && $this->subject === $this->clientId
            && ! array_key_exists('act', $this->claims);
    }

    /**
     * RFC 8693 §4.1: the subject of the party ACTING for this token's subject — set on a
     * support session's token — or null. Read like `cnf`: a JWT decode yields a stdClass.
     */
    public function actorSubject(): ?string
    {
        $act = $this->claims['act'] ?? null;

        if (is_object($act)) {
            $act = (array) $act;
        }

        $subject = is_array($act) ? ($act['sub'] ?? null) : null;

        return is_string($subject) && $subject !== '' ? $subject : null;
    }

    /**
     * The DPoP confirmation thumbprint (`cnf.jkt`, RFC 9449) this token is
     * sender-constrained to, or null for a plain bearer token.
     */
    public function confirmationThumbprint(): ?string
    {
        // `cnf` may arrive as an array or, from a JWT decode, a stdClass — cast so
        // both shapes resolve.
        $cnf = $this->claims['cnf'] ?? null;

        if (is_object($cnf)) {
            $cnf = (array) $cnf;
        }

        if (! is_array($cnf)) {
            return null;
        }

        $jkt = $cnf['jkt'] ?? null;

        return is_string($jkt) && $jkt !== '' ? $jkt : null;
    }
}
