<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\Api\Support\ServerMetadata;
use Cbox\Id\ExternalActions\Exceptions\ActionDenied;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Support\Base64Url;
use Cbox\Id\OAuthServer\Contracts\AuthorizationCodes;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\DeviceAuthorization;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\OAuthServer\Contracts\TokenExchange;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\OAuthServer\Dpop\DpopProofValidator;
use Cbox\Id\OAuthServer\Exceptions\CibaAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\CibaAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\CibaExpired;
use Cbox\Id\OAuthServer\Exceptions\CibaSlowDown;
use Cbox\Id\OAuthServer\Exceptions\DeviceAccessDenied;
use Cbox\Id\OAuthServer\Exceptions\DeviceAuthorizationPending;
use Cbox\Id\OAuthServer\Exceptions\DeviceExpired;
use Cbox\Id\OAuthServer\Exceptions\DeviceSlowDown;
use Cbox\Id\OAuthServer\Exceptions\InvalidDpopProof;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Exceptions\InvalidTokenExchange;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizedGrant;
use Cbox\Id\OAuthServer\ValueObjects\IssuedToken;
use Cbox\Id\OAuthServer\ValueObjects\RefreshGrant;
use Cbox\Id\OAuthServer\ValueObjects\TokenExchangeRequest;
use Cbox\Id\Organization\Contracts\Organizations;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * `POST /oauth/token` — the token endpoint. Supports `client_credentials` (M2M),
 * `authorization_code` with mandatory PKCE (S256), and `refresh_token` with
 * rotation + reuse detection. Access tokens and the id_token are RS256 JWTs
 * signed by the Crypto kernel. Tokens can be audience-bound via the RFC 8707
 * `resource` parameter.
 */
class TokenController
{
    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly AuthorizationCodes $codes,
        private readonly TokenIssuer $issuer,
        private readonly TokenSigner $signer,
        private readonly RefreshTokens $refreshTokens,
        private readonly DpopProofValidator $dpop,
        private readonly DeviceAuthorization $device,
        private readonly BackchannelAuthentication $ciba,
        private readonly Organizations $organizations,
        private readonly TokenExchange $exchange,
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

        // RFC 8707 §2: a present-but-malformed `resource` is an error, not a token
        // silently issued unbound (which would over-scope it to every audience).
        if ($this->resourceIsMalformed($request)) {
            return $this->error('invalid_target', 400);
        }

        try {
            return match ($request->string('grant_type')->toString()) {
                'client_credentials' => $this->clientCredentials($request, $jkt),
                'authorization_code' => $this->authorizationCode($request, $jkt),
                'refresh_token' => $this->refreshToken($request, $jkt),
                'urn:ietf:params:oauth:grant-type:device_code' => $this->deviceCode($request, $jkt),
                'urn:openid:params:grant-type:ciba' => $this->ciba($request, $jkt),
                'urn:ietf:params:oauth:grant-type:token-exchange' => $this->tokenExchange($request, $jkt),
                default => $this->error('unsupported_grant_type', 400),
            };
        } catch (ActionDenied) {
            // A TokenMinting inline hook vetoed issuance (fires on every grant).
            return $this->error('access_denied', 400);
        }
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
        $client = $this->clientAuth->authenticateConfidential($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'client_credentials')) {
            return $this->error('unauthorized_client', 400);
        }

        return $this->tokenResponse(
            $this->issuer->issueClientCredentials($client, $this->scopes($request), $this->resource($request), $dpopJkt),
            null,
        );
    }

    private function authorizationCode(Request $request, ?string $dpopJkt): JsonResponse
    {
        // Confidential clients must authenticate with their secret in addition to
        // PKCE (RFC 6749 §4.1.3). PKCE alone is the guard for public clients, which
        // hold no secret. Secrets are verified in constant time by the registry.
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'authorization_code')) {
            return $this->error('unauthorized_client', 400);
        }

        try {
            $grant = $this->codes->exchange(
                $client->client_id,
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
        // If this token exchange was DPoP-bound, bind the refresh token to the same
        // key (RFC 9449 §5) so rotation demands proof of possession.
        $refresh = in_array('offline_access', $grant->scopes, true)
            ? $this->refreshTokens->issue($client, $grant->userId, $grant->organizationId, $grant->scopes, $resource, $dpopJkt)
            : null;

        return $this->tokenResponse($access, $this->idToken($client->client_id, $grant, $access), $refresh);
    }

    private function deviceCode(Request $request, ?string $dpopJkt): JsonResponse
    {
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'urn:ietf:params:oauth:grant-type:device_code')) {
            return $this->error('unauthorized_client', 400);
        }

        try {
            $grant = $this->device->redeem($client->client_id, $request->string('device_code')->toString());
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

    private function ciba(Request $request, ?string $dpopJkt): JsonResponse
    {
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'urn:openid:params:grant-type:ciba')) {
            return $this->error('unauthorized_client', 400);
        }

        try {
            $grant = $this->ciba->redeem($client->client_id, $request->string('auth_req_id')->toString());
        } catch (CibaAuthorizationPending) {
            return $this->error('authorization_pending', 400);
        } catch (CibaSlowDown) {
            return $this->error('slow_down', 400);
        } catch (CibaAccessDenied) {
            return $this->error('access_denied', 400);
        } catch (CibaExpired) {
            return $this->error('expired_token', 400);
        } catch (InvalidGrant) {
            return $this->error('invalid_grant', 400);
        }

        // CIBA is OpenID Connect: the token response carries an id_token bound to
        // the approving user (with auth_time and the request nonce).
        $access = $this->issuer->issueForUser($client, $grant->userId, $grant->organizationId, $grant->scopes, null, $dpopJkt);

        return $this->tokenResponse($access, $this->idToken($client->client_id, $grant, $access));
    }

    private function refreshToken(Request $request, ?string $dpopJkt): JsonResponse
    {
        $client = $this->clientAuth->authenticate($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'refresh_token')) {
            return $this->error('unauthorized_client', 400);
        }

        try {
            $rotated = $this->refreshTokens->rotate($client->client_id, $request->string('refresh_token')->toString(), $dpopJkt);
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
        $now = time();

        $claims = [
            // Per-environment issuer — matches discovery + the access-token `iss`.
            'iss' => ServerMetadata::issuer(),
            'sub' => $grant->userId,
            'aud' => $clientId,
            'org' => $grant->organizationId,
            'iat' => $now,
            'exp' => $now + 900,
            // OIDC Core 3.1.3.6: binds the id_token to the issued access token.
            'at_hash' => $this->atHash($access->token),
        ];

        // Human-readable org name alongside the id, so the relying party can label
        // the organization (e.g. in its own top bar) without a second lookup.
        if ($grant->organizationId !== null) {
            $orgName = $this->organizations->find($grant->organizationId)?->name;
            if (is_string($orgName) && $orgName !== '') {
                $claims['org_name'] = $orgName;
            }
        }

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

    /**
     * RFC 8707 resource indicator. Returns a well-formed absolute URI, or null
     * when none was requested. A malformed value is rejected upfront in
     * {@see resourceIsMalformed()}, so by here a non-null value is well-formed.
     */
    private function resource(Request $request): ?string
    {
        $resource = trim($request->string('resource')->toString());

        return $resource === '' ? null : $resource;
    }

    /**
     * A `resource` was supplied but is not an absolute URI (RFC 8707 requires an
     * absolute URI, and forbids a fragment). Absent `resource` is not malformed.
     */
    private function resourceIsMalformed(Request $request): bool
    {
        $resource = trim($request->string('resource')->toString());

        if ($resource === '') {
            return false;
        }

        $parts = parse_url($resource);

        return ! is_array($parts) || ! isset($parts['scheme'], $parts['host']) || isset($parts['fragment']);
    }

    /**
     * @return list<string>
     */
    private function scopes(Request $request): array
    {
        $scope = $request->string('scope')->toString();

        return $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));
    }

    /**
     * RFC 8693 token exchange — exchange a valid subject access token for a new,
     * down-scoped and/or re-audienced access token. Requires client authentication.
     */
    private function tokenExchange(Request $request, ?string $dpopJkt): JsonResponse
    {
        $client = $this->clientAuth->authenticateConfidential($request);

        if ($client === null) {
            return $this->error('invalid_client', 401);
        }

        // RFC 6749 §5.2: a client may only use the grants it registered for.
        if (! $this->grantAllowed($client, 'urn:ietf:params:oauth:grant-type:token-exchange')) {
            return $this->error('unauthorized_client', 400);
        }

        $subjectToken = $request->string('subject_token')->toString();
        $subjectTokenType = $request->string('subject_token_type')->toString();

        if ($subjectToken === '' || $subjectTokenType === '') {
            return $this->error('invalid_request', 400);
        }

        try {
            $result = $this->exchange->exchange($client, new TokenExchangeRequest(
                subjectToken: $subjectToken,
                subjectTokenType: $subjectTokenType,
                requestedScopes: $this->scopes($request),
                resource: $this->resource($request),
                dpopJkt: $dpopJkt,
                requestedTokenType: $request->string('requested_token_type')->toString() ?: null,
            ));
        } catch (InvalidTokenExchange $e) {
            return $this->error($e->error, 400);
        }

        return new JsonResponse([
            'access_token' => $result->token->token,
            'issued_token_type' => TokenExchangeRequest::ACCESS_TOKEN_TYPE,
            'token_type' => $result->token->tokenType,
            'expires_in' => $result->token->expiresIn,
            // RFC 8693 §2.2.1: echo the granted scope (REQUIRED when it differs from
            // the request — e.g. an empty request that inherited the subject scopes).
            'scope' => implode(' ', $result->scopes),
        ]);
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

    /**
     * May this client use this grant?
     *
     * `grant_types` was stored at registration, echoed back in the registration
     * document, and enforced NOWHERE — the token endpoint dispatched purely on the
     * grant_type the caller asked for, so an authorization-code-only client could
     * request client_credentials and be issued a token. The registered policy was
     * decorative.
     *
     * An empty list means the client predates the field; treat that as
     * authorization_code only rather than as "anything", so the default is closed.
     */
    private function grantAllowed(Client $client, string $grantType): bool
    {
        $registered = $client->grant_types;

        if ($registered === []) {
            return $grantType === 'authorization_code';
        }

        return in_array($grantType, $registered, true);
    }

    private function error(string $error, int $status): JsonResponse
    {
        return new JsonResponse(['error' => $error], $status);
    }
}
