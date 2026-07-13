<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\Kernel\Authorization\Contracts\EntitlementReader;
use Cbox\Id\Kernel\Authorization\Enums\EnforcementMode;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Models\AccessToken;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Illuminate\Support\Str;

/**
 * Issues stateless RS256 JWT access tokens (signed by the Crypto kernel) and
 * records each `jti` so tokens remain revocable and introspectable.
 */
final class JwtTokenIssuer implements TokenIssuer
{
    private const TTL_SECONDS = 900;

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly EntitlementReader $entitlements,
    ) {}

    public function issueClientCredentials(Client $client, array $scopes = [], ?string $resource = null, ?string $dpopJkt = null): IssuedToken
    {
        return $this->issue($client, $client->client_id, null, $client->organization_id, $this->grantScopes($client, $scopes), $resource, $dpopJkt);
    }

    public function issueForUser(Client $client, string $userId, ?string $organizationId, array $scopes = [], ?string $resource = null, ?string $dpopJkt = null): IssuedToken
    {
        return $this->issue($client, $userId, $userId, $organizationId, $this->grantScopes($client, $scopes), $resource, $dpopJkt);
    }

    /**
     * The org's Claims-mode entitlements to embed in a token, plus the highest
     * version among them (a staleness signal). Returns `[[], 0]` when disabled or
     * when the org has no Claims-mode entitlements.
     *
     * @return array{0: array<string, array<string, mixed>>, 1: int}
     */
    private function claimsEntitlements(string $organizationId): array
    {
        if (config('cbox-id.oauth.embed_entitlements', true) !== true) {
            return [[], 0];
        }

        $embedded = [];
        $version = 0;

        foreach ($this->entitlements->all($organizationId) as $key => $value) {
            if ($value->mode !== EnforcementMode::Claims) {
                continue; // instant-critical keys stay live, never baked into a token
            }

            $embedded[$key] = $value->value;
            $version = max($version, $value->version);
        }

        return [$embedded, $version];
    }

    /**
     * @param  list<string>  $requested
     * @return list<string>
     */
    private function grantScopes(Client $client, array $requested): array
    {
        if ($requested === []) {
            return array_values($client->scopes);
        }

        return array_values(array_filter($requested, fn (string $scope): bool => $client->allows($scope)));
    }

    /**
     * @param  list<string>  $scopes
     */
    private function issue(Client $client, string $subject, ?string $userId, ?string $organizationId, array $scopes, ?string $resource = null, ?string $dpopJkt = null): IssuedToken
    {
        $jti = (string) Str::ulid();
        $issuedAt = time();

        $claims = [
            'iss' => 'cbox-id',
            'sub' => $subject,
            'client_id' => $client->client_id,
            'jti' => $jti,
            'scope' => implode(' ', $scopes),
            'org' => $organizationId,
            'iat' => $issuedAt,
            'exp' => $issuedAt + self::TTL_SECONDS,
        ];

        // RFC 8707 / 9068: bind the token to the requested resource server so it
        // can verify the token was minted for it (confused-deputy defense, which
        // the MCP authorization model depends on).
        if ($resource !== null) {
            $claims['aud'] = $resource;
        }

        // RFC 9449: sender-constrain the token to the client's DPoP key. A resource
        // server compares this jkt to the thumbprint of the proof presented with the
        // token, so a stolen bearer alone is useless.
        if ($dpopJkt !== null) {
            $claims['cnf'] = ['jkt' => $dpopJkt];
        }

        // Hybrid entitlements (WorkOS-style): the coarse, Claims-mode entitlements
        // are embedded so a resource server can gate statelessly with no round trip.
        // Only Claims-mode keys are included; instant-critical ones stay DecisionApi
        // (live via /oauth/decisions). `ent_ver` lets a consumer detect staleness.
        if ($organizationId !== null) {
            [$entitlements, $version] = $this->claimsEntitlements($organizationId);
            if ($entitlements !== []) {
                $claims['ent'] = $entitlements;
                $claims['ent_ver'] = $version;
            }
        }

        // RFC 9068: OAuth access tokens carry the `at+jwt` media type.
        $token = $this->signer->sign($claims, type: 'at+jwt');

        AccessToken::query()->create([
            'jti' => $jti,
            'client_id' => $client->client_id,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'scopes' => $scopes,
            'audience' => $resource,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
        ]);

        return new IssuedToken($token, $jti, self::TTL_SECONDS, $dpopJkt !== null ? 'DPoP' : 'Bearer');
    }
}
