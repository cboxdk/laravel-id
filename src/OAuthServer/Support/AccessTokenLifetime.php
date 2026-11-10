<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Cbox\Id\Kernel\Presentation\ValueObjects\SourceMessage;
use Cbox\Id\OAuthServer\Exceptions\InvalidClientMetadata;
use Cbox\Id\OAuthServer\Models\Client;

/**
 * How long a client's access tokens (and ID tokens) live — one rule, read by every grant.
 *
 * A client's own `access_token_ttl` wins when it has one; null means the deployment
 * default (`cbox-id.oauth.access_token_ttl`). The client's value is bounded by
 * `cbox-id.oauth.max_access_token_ttl` twice: refused above it when it is SET, and clamped
 * to it when a token is MINTED — so an operator who lowers the ceiling shortens every
 * client already above it on the next token, rather than only the ones registered after.
 *
 * The deployment default is not clamped. It is the operator's own number, and quietly
 * shortening it on upgrade would change every token in the deployment unannounced.
 *
 * One exception sits above both: `cbox-id.oauth.scope_token_ttls` gives a token whose
 * scopes are EXACTLY a configured set its own lifetime ({@see forScopes()}). It exists for
 * narrow, read-only grants such as `account:apps:read` (the app switcher's catalog), where
 * a fifteen-minute token only means a broken switcher. It is clamped to the ceiling too.
 */
class AccessTokenLifetime
{
    /**
     * The shortest lifetime a client may ask for. Below a minute, a token is expired by
     * clock skew between the issuer and a resource server before it is used.
     */
    public const MIN_SECONDS = 60;

    /** The ceiling when none is configured: one day. */
    public const DEFAULT_MAX_SECONDS = 86400;

    private const DEFAULT_SECONDS = 900;

    /**
     * The lifetime of a token minted for this client, in seconds.
     *
     * @param  int|null  $default  the deployment default; read from config when null
     */
    public static function for(Client $client, ?int $default = null): int
    {
        $ttl = $client->access_token_ttl;
        if ($ttl === null || $ttl <= 0) {
            return $default ?? self::deploymentDefault();
        }

        return min($ttl, self::max());
    }

    /**
     * The lifetime configured for a token carrying exactly these scopes, or null when
     * `cbox-id.oauth.scope_token_ttls` names no such set.
     *
     * A key is a space-separated scope set; it matches only when the token's scopes are the
     * same set (order does not matter). A token with one scope more or one fewer is not a
     * match, so widening a grant never inherits a long lifetime. A value that is not a
     * positive number disables its entry. The result is clamped to {@see max()}.
     *
     * @param  list<string>  $scopes
     */
    public static function forScopes(array $scopes): ?int
    {
        $configured = config('cbox-id.oauth.scope_token_ttls', []);
        if (! is_array($configured) || $scopes === []) {
            return null;
        }

        $granted = self::normalize($scopes);

        foreach ($configured as $set => $ttl) {
            if (! is_string($set) || ! is_numeric($ttl) || (int) $ttl <= 0) {
                continue;
            }

            if (self::normalize(preg_split('/\s+/', $set, -1, PREG_SPLIT_NO_EMPTY) ?: []) === $granted) {
                return min((int) $ttl, self::max());
            }
        }

        return null;
    }

    /**
     * @param  array<array-key, string>  $scopes
     * @return list<string>
     */
    private static function normalize(array $scopes): array
    {
        $scopes = array_values(array_unique($scopes));
        sort($scopes);

        return $scopes;
    }

    /**
     * Refuse a per-client lifetime outside [MIN_SECONDS, max]. Null (use the default) is
     * always accepted.
     *
     * @throws InvalidClientMetadata
     */
    public static function assertAcceptable(?int $ttl): void
    {
        if ($ttl === null) {
            return;
        }
        $max = self::max();
        if ($ttl < self::MIN_SECONDS || $ttl > $max) {
            throw InvalidClientMetadata::metadata(sprintf('access_token_ttl must be between %d and %d seconds (or null for the deployment default); %d was given', self::MIN_SECONDS, $max, $ttl))->withSourceMessage(new SourceMessage('access_token_ttl must be between :value1 and :max seconds (or null for the deployment default); :ttl was given', ['value1' => self::MIN_SECONDS, 'max' => $max, 'ttl' => $ttl]));
        }
    }

    public static function max(): int
    {
        $max = config('cbox-id.oauth.max_access_token_ttl', self::DEFAULT_MAX_SECONDS);

        return is_numeric($max) && (int) $max >= self::MIN_SECONDS ? (int) $max : self::DEFAULT_MAX_SECONDS;
    }

    public static function deploymentDefault(): int
    {
        $default = config('cbox-id.oauth.access_token_ttl', self::DEFAULT_SECONDS);

        return is_numeric($default) ? (int) $default : self::DEFAULT_SECONDS;
    }
}
