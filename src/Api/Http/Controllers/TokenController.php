<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/token` — the token endpoint. Supports `client_credentials` (M2M)
 * and `authorization_code` with mandatory PKCE (S256). Access tokens and the
 * id_token are RS256 JWTs signed by the Crypto kernel.
 */
final class TokenController
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly AuthorizationCodes $codes,
        private readonly TokenIssuer $issuer,
        private readonly TokenSigner $signer,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        return match ($request->string('grant_type')->toString()) {
            'client_credentials' => $this->clientCredentials($request),
            'authorization_code' => $this->authorizationCode($request),
            default => $this->error('unsupported_grant_type', 400),
        };
    }

    private function clientCredentials(Request $request): JsonResponse
    {
        $client = $this->authenticateClient($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        return $this->tokenResponse($this->issuer->issueClientCredentials($client, $this->scopes($request)), null);
    }

    private function authorizationCode(Request $request): JsonResponse
    {
        $clientId = $request->string('client_id')->toString();
        $client = $this->clients->byClientId($clientId);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // Confidential clients must authenticate with their secret in addition to
        // PKCE (RFC 6749 §4.1.3). PKCE alone is the guard for public clients, which
        // hold no secret. Verified in constant time by the registry.
        if ($client->type === ClientType::Confidential
            && ! $this->clients->verifySecret($client, $request->string('client_secret')->toString())) {
            return $this->error('invalid_client', 401);
        }

        try {
            $grant = $this->codes->exchange(
                $clientId,
                $request->string('code')->toString(),
                $request->string('redirect_uri')->toString(),
                $request->string('code_verifier')->toString(),
            );
        } catch (InvalidGrant) {
            return $this->error('invalid_grant', 400);
        }

        $access = $this->issuer->issueForUser($client, $grant->userId, $grant->organizationId, $grant->scopes);

        return $this->tokenResponse($access, $this->idToken($clientId, $grant));
    }

    private function idToken(string $clientId, AuthorizedGrant $grant): string
    {
        $issuer = config('cbox-id.issuer');
        $now = time();

        $claims = [
            'iss' => is_string($issuer) && $issuer !== '' ? $issuer : 'cbox-id',
            'sub' => $grant->userId,
            'aud' => $clientId,
            'org' => $grant->organizationId,
            'iat' => $now,
            'exp' => $now + 900,
        ];

        // OIDC Core 3.1.3.6: echo the request nonce so the client can bind the
        // id_token to its authorization request and detect replay.
        if ($grant->nonce !== null) {
            $claims['nonce'] = $grant->nonce;
        }

        return $this->signer->sign($claims);
    }

    private function authenticateClient(Request $request): ?Client
    {
        $client = $this->clients->byClientId($request->string('client_id')->toString());

        return $client !== null && $this->clients->verifySecret($client, $request->string('client_secret')->toString())
            ? $client
            : null;
    }

    /**
     * @return list<string>
     */
    private function scopes(Request $request): array
    {
        $scope = $request->string('scope')->toString();

        return $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));
    }

    private function tokenResponse(IssuedToken $token, ?string $idToken): JsonResponse
    {
        $body = [
            'access_token' => $token->token,
            'token_type' => 'Bearer',
            'expires_in' => $token->expiresIn,
        ];

        if ($idToken !== null) {
            $body['id_token'] = $idToken;
        }

        return new JsonResponse($body);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status);
    }
}
