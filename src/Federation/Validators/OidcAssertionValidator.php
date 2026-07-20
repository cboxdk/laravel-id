<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Validators;

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Throwable;

/**
 * Validates an OpenID Connect `id_token` (a JWS) against a connection's config.
 *
 * Security posture:
 *  - Signature verification is delegated to firebase/php-jwt (vetted, maintained).
 *  - The verification key(s) are pinned to RS256 via {@see Key}, so a token whose
 *    header advertises a different `alg` (e.g. `HS256`, `none`) is rejected —
 *    closing the classic algorithm-confusion hole.
 *  - `exp`/`nbf`/`iat` are enforced by the library; `iss` and `aud` are asserted
 *    against the connection's configured issuer and client id here.
 *
 * The connection config (sealed at rest) must contain:
 *  - `issuer`     — the exact expected `iss`
 *  - `client_id`  — must appear in the token's `aud`
 *  - one of:
 *      `signing_keys` — map of `kid` → PEM public key (JWKS-style, multi-key)
 *      `signing_key`  — a single PEM public key (used when the IdP omits `kid`)
 */
class OidcAssertionValidator implements AssertionValidator
{
    private const ALG = 'RS256';

    public function __construct(private readonly Connections $connections) {}

    public function validate(Connection $connection, string $rawResponse): FederatedPrincipal
    {
        $config = $this->connections->config($connection);

        $issuer = $this->requireString($config, 'issuer');
        $clientId = $this->requireString($config, 'client_id');

        $claims = $this->decode($rawResponse, $config);

        $this->assertIssuer($claims, $issuer);
        $this->assertAudience($claims, $clientId);

        $subject = isset($claims['sub']) && is_string($claims['sub']) ? $claims['sub'] : null;

        if ($subject === null || $subject === '') {
            throw InvalidAssertion::make('missing subject (sub)');
        }

        return new FederatedPrincipal(
            provider: $connection->type->value,
            subject: $subject,
            email: $this->optionalString($claims, 'email'),
            name: $this->optionalString($claims, 'name'),
            connectionId: $connection->id,
            raw: $claims,
        );
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     */
    private function decode(string $idToken, array $config): array
    {
        try {
            $decoded = JWT::decode($idToken, $this->keys($config));
        } catch (Throwable $exception) {
            throw InvalidAssertion::make('signature or lifetime check failed: '.$exception->getMessage());
        }

        $claims = [];
        foreach (get_object_vars($decoded) as $name => $value) {
            $claims[(string) $name] = $value;
        }

        return $claims;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return Key|array<string, Key>
     */
    private function keys(array $config): Key|array
    {
        $keySet = $config['signing_keys'] ?? null;

        if (is_array($keySet) && $keySet !== []) {
            $keys = [];
            foreach ($keySet as $kid => $pem) {
                if (is_string($pem) && $pem !== '') {
                    $keys[(string) $kid] = new Key($pem, self::ALG);
                }
            }

            if ($keys !== []) {
                return $keys;
            }
        }

        $single = $config['signing_key'] ?? null;

        if (is_string($single) && $single !== '') {
            return new Key($single, self::ALG);
        }

        throw InvalidAssertion::make('connection has no signing key configured');
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertIssuer(array $claims, string $issuer): void
    {
        $iss = $claims['iss'] ?? null;

        if (! is_string($iss) || ! hash_equals($issuer, $iss)) {
            throw InvalidAssertion::make('issuer mismatch');
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function assertAudience(array $claims, string $clientId): void
    {
        $aud = $claims['aud'] ?? null;
        $audiences = is_array($aud) ? $aud : [$aud];

        foreach ($audiences as $candidate) {
            if (is_string($candidate) && hash_equals($clientId, $candidate)) {
                return;
            }
        }

        throw InvalidAssertion::make('audience mismatch');
    }

    /**
     * @param  array<string, mixed>  $config
     */
    private function requireString(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw InvalidAssertion::make("connection config missing [{$key}]");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function optionalString(array $claims, string $key): ?string
    {
        $value = $claims[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
