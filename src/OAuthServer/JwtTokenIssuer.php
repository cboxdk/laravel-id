<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
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
 *
 * Just before signing, the {@see HookPoint::TokenMinting} inline hook runs
 * ({@see ActionPipeline}): registered actions may enrich the token with extra claims
 * or veto issuance. Reserved protocol/security claims can never be overwritten, and a
 * veto throws {@see ActionDenied} before any `jti` is recorded — so a denied token
 * leaves no trace.
 */
final class JwtTokenIssuer implements TokenIssuer
{
    private const TTL_SECONDS = 900;

    /**
     * Claims a hook may never set or overwrite — the protocol/security-bearing ones.
     * Enrichment that names any of these is dropped.
     */
    private const RESERVED_CLAIMS = ['iss', 'sub', 'client_id', 'jti', 'scope', 'org', 'iat', 'exp', 'nbf', 'aud', 'cnf', 'ent', 'ent_ver', 'typ'];

    public function __construct(
        private readonly TokenSigner $signer,
        private readonly EntitlementReader $entitlements,
        private readonly ActionPipeline $actions,
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
     * Fold a hook's enrichment into the claims, skipping any reserved key — a hook
     * can add custom claims but never rewrite `sub`, `exp`, `scope`, `aud`, etc.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $enrichment
     * @return array<string, mixed>
     */
    private function applyEnrichment(array $claims, array $enrichment): array
    {
        foreach ($enrichment as $key => $value) {
            // Keys are string-typed by contract; a reserved claim is never overwritten.
            if (in_array($key, self::RESERVED_CLAIMS, true)) {
                continue;
            }

            $claims[$key] = $value;
        }

        return $claims;
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

        // Inline hook: let registered actions enrich the claims or veto issuance,
        // with the fully-assembled base claims in context. Runs before the jti row is
        // written, so a veto leaves nothing behind.
        $outcome = $this->actions->run(HookPoint::TokenMinting, new ActionContext(HookPoint::TokenMinting, [
            'client_id' => $client->client_id,
            'subject' => $subject,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'scopes' => $scopes,
            'grant' => $userId === null ? 'client_credentials' : 'user',
            'claims' => $claims,
        ]));

        if (! $outcome->allowed) {
            throw ActionDenied::because($outcome->reason);
        }

        $claims = $this->applyEnrichment($claims, $outcome->enrichment);

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
