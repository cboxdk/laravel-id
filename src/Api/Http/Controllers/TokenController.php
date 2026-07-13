<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\DeviceAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\DeviceAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\DeviceExpired;
use Cbox\Id\OAuthServer\Exceptions\DeviceSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Cbox\Id\OAuthServer\ValueObjects\RefreshGrant;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/token` — the token endpoint. Supports `client_credentials` (M2M),
 * `authorization_code` with mandatory PKCE (S256), and `refresh_token` with
 * rotation + reuse detection. Access tokens and the id_token are RS256 JWTs
 * signed by the Crypto kernel. Tokens can be audience-bound via the RFC 8707
 * `resource` parameter.
 */
final class TokenController
{
    public function __construct(
        private readonly ClientRegistry $clients,
        private readonly AuthorizationCodes $codes,
        private readonly TokenIssuer $issuer,
        private readonly TokenSigner $signer,
        private readonly RefreshTokens $refreshTokens,
        private readonly DpopProofValidator $dpop,
        private readonly DeviceAuthorization $device,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        // RFC 9449: a DPoP header sender-constrains the issued token to the client's
        // key. Validate it once (against this method+URL) and thread the thumbprint
        // into whichever grant runs.
        try {
            $jkt = $this->dpopBinding($request);
        } catch (InvalidDpopProof) {
            return $this->error('invalid_dpop_proof', 400);
        }

        return match ($request->string('grant_type')->toString()) {
            'client_credentials' => $this->clientCredentials($request, $jkt),
            'authorization_code' => $this->authorizationCode($request, $jkt),
            'refresh_token' => $this->refreshToken($request, $jkt),
            'urn:ietf:params:oauth:grant-type:device_code' => $this->deviceCode($request, $jkt),
            default => $this->error('unsupported_grant_type', 400),
        };
    }

    private function dpopBinding(Request $request): ?string
    {
        $proof = $request->header('DPoP');

        if (! is_string($proof) || $proof === '') {
            return null;
        }

        return $this->dpop->verify($proof, $request->method(), $request->url());
    }

    private function clientCredentials(Request $request, ?string $dpopJkt): JsonResponse
    {
        $client = $this->authenticateClient($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        return $this->tokenResponse(
            $this->issuer->issueClientCredentials($client, $this->scopes($request), $this->resource($request), $dpopJkt),
            null,
        );
    }

    private function authorizationCode(Request $request, ?string $dpopJkt): JsonResponse
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

        $resource = $this->resource($request);
        $access = $this->issuer->issueForUser($client, $grant->userId, $grant->organizationId, $grant->scopes, $resource, $dpopJkt);

        // A refresh token is issued only when the client asked for offline access.
        $refresh = in_array('offline_access', $grant->scopes, true)
            ? $this->refreshTokens->issue($client, $grant->userId, $grant->organizationId, $grant->scopes, $resource)
            : null;

        return $this->tokenResponse($access, $this->idToken($clientId, $grant, $access), $refresh);
    }

    private function deviceCode(Request $request, ?string $dpopJkt): JsonResponse
    {
        $clientId = $request->string('client_id')->toString();
        $client = $this->clients->byClientId($clientId);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        if ($client->secret_hash !== null
            && ! $this->clients->verifySecret($client, $request->string('client_secret')->toString())) {
            return $this->error('invalid_client', 401);
        }

        try {
            $grant = $this->device->redeem($clientId, $request->string('device_code')->toString());
        } catch (DeviceAuthorizationPending) {
            return $this->error('authorization_pending', 400);
        } catch (DeviceSlowDown) {
            return $this->error('slow_down', 400);
        } catch (DeviceAccessDenied) {
            return $this->error('access_denied', 400);
        } catch (DeviceExpired) {
            return $this->error('expired_token', 400);
        } catch (InvalidGrant) {
            return $this->error('invalid_grant', 400);
        }

        return $this->tokenResponse(
            $this->issuer->issueForUser($client, $grant->userId, $grant->organizationId, $grant->scopes, null, $dpopJkt),
            null,
        );
    }

    private function refreshToken(Request $request, ?string $dpopJkt): JsonResponse
    {
        $clientId = $request->string('client_id')->toString();
        $client = $this->clients->byClientId($clientId);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        if ($client->type === ClientType::Confidential
            && ! $this->clients->verifySecret($client, $request->string('client_secret')->toString())) {
            return $this->error('invalid_client', 401);
        }

        try {
            $rotated = $this->refreshTokens->rotate($clientId, $request->string('refresh_token')->toString());
        } catch (InvalidGrant) {
            return $this->error('invalid_grant', 400);
        }

        return $this->tokenResponse($this->accessFromRefresh($client, $rotated, $dpopJkt), null, $rotated->refreshToken);
    }

    private function accessFromRefresh(Client $client, RefreshGrant $grant, ?string $dpopJkt): IssuedToken
    {
        return $grant->userId !== null
            ? $this->issuer->issueForUser($client, $grant->userId, $grant->organizationId, $grant->scopes, $grant->audience, $dpopJkt)
            : $this->issuer->issueClientCredentials($client, $grant->scopes, $grant->audience, $dpopJkt);
    }

    private function idToken(string $clientId, AuthorizedGrant $grant, IssuedToken $access): string
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
            // OIDC Core 3.1.3.6: binds the id_token to the issued access token.
            'at_hash' => $this->atHash($access->token),
        ];

        // OIDC Core 3.1.3.6: echo the request nonce so the client can bind the
        // id_token to its authorization request and detect replay.
        if ($grant->nonce !== null) {
            $claims['nonce'] = $grant->nonce;
        }

        // Authentication context, for the client's step-up / re-auth decisions.
        if ($grant->authTime !== null) {
            $claims['auth_time'] = $grant->authTime;
        }

        if ($grant->amr !== []) {
            $claims['amr'] = $grant->amr;
            // acr: a stronger login (a second factor was used) is level 2.
            $stepUp = array_intersect($grant->amr, ['mfa', 'otp', 'passkey', 'webauthn']) !== [];
            $claims['acr'] = $stepUp ? 'urn:cbox-id:aal2' : 'urn:cbox-id:aal1';
        }

        return $this->signer->sign($claims);
    }

    /**
     * OIDC `at_hash`: base64url of the left half of SHA-256 of the access token.
     */
    private function atHash(string $accessToken): string
    {
        $digest = hash('sha256', $accessToken, true);

        return Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
    }

    private function authenticateClient(Request $request): ?Client
    {
        $client = $this->clients->byClientId($request->string('client_id')->toString());

        return $client !== null && $this->clients->verifySecret($client, $request->string('client_secret')->toString())
            ? $client
            : null;
    }

    /**
     * RFC 8707 resource indicator. Returns a well-formed absolute URI, or null
     * when none was requested (or it was malformed — the token is then unbound).
     */
    private function resource(Request $request): ?string
    {
        $resource = trim($request->string('resource')->toString());

        if ($resource === '') {
            return null;
        }

        $parts = parse_url($resource);

        return is_array($parts) && isset($parts['scheme'], $parts['host']) ? $resource : null;
    }

    /**
     * @return list<string>
     */
    private function scopes(Request $request): array
    {
        $scope = $request->string('scope')->toString();

        return $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));
    }

    private function tokenResponse(IssuedToken $token, ?string $idToken, ?string $refreshToken = null): JsonResponse
    {
        $body = [
            'access_token' => $token->token,
            'token_type' => $token->tokenType,
            'expires_in' => $token->expiresIn,
        ];

        if ($idToken !== null) {
            $body['id_token'] = $idToken;
        }

        if ($refreshToken !== null) {
            $body['refresh_token'] = $refreshToken;
        }

        return new JsonResponse($body);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status);
    }
}
