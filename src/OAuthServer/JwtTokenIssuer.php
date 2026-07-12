<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer;

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

    public function __construct(private readonly TokenSigner $signer) {}

    public function issueClientCredentials(Client $client, array $scopes = [], ?string $resource = null): IssuedToken
    {
        return $this->issue($client, $client->client_id, null, $client->organization_id, $this->grantScopes($client, $scopes), $resource);
    }

    public function issueForUser(Client $client, string $userId, ?string $organizationId, array $scopes = [], ?string $resource = null): IssuedToken
    {
        return $this->issue($client, $userId, $userId, $organizationId, $this->grantScopes($client, $scopes), $resource);
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
    private function issue(Client $client, string $subject, ?string $userId, ?string $organizationId, array $scopes, ?string $resource = null): IssuedToken
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

        $token = $this->signer->sign($claims);

        AccessToken::query()->create([
            'jti' => $jti,
            'client_id' => $client->client_id,
            'user_id' => $userId,
            'organization_id' => $organizationId,
            'scopes' => $scopes,
            'audience' => $resource,
            'expires_at' => now()->addSeconds(self::TTL_SECONDS),
        ]);

        return new IssuedToken($token, $jti, self::TTL_SECONDS);
    }
}
