<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers;

use Cbox\Id\Api\Support\ClientAuthenticator;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Contracts\CibaClientNotifications;
use Cbox\Id\OAuthServer\Enums\BackchannelTokenDeliveryMode;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Exceptions\CibaRateLimited;
use Cbox\Id\OAuthServer\Exceptions\InvalidAudience;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGranted;
use Cbox\Id\OAuthServer\Exceptions\UnknownUserHint;
use Cbox\Id\OAuthServer\Support\DynamicGrantPolicy;
use Cbox\Id\OAuthServer\Support\GrantPolicy;
use Cbox\Id\OAuthServer\Support\ResourceParameter;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

/**
 * `POST /oauth/backchannel_authentication` — the CIBA backchannel authentication
 * endpoint (OpenID Connect CIBA Core §7). A client (typically an autonomous / AI
 * agent) starts a decoupled authentication here by naming the user with
 * `login_hint`; the user approves out-of-band, and the client then polls the token
 * endpoint with the returned `auth_req_id` — or, registered for ping mode, is told at its
 * notification endpoint and calls the token endpoint once.
 */
class BackchannelAuthenticationController
{
    /** The longest binding message stored and shown to the person approving. */
    public const int BINDING_MESSAGE_MAX = 255;

    /** CIBA Core §7.1: a client_notification_token MUST NOT exceed 1024 characters. */
    public const int CLIENT_NOTIFICATION_TOKEN_MAX = 1024;

    /** Requests one client may file for one login_hint in the window below. */
    private const DEFAULT_PER_CLIENT_HINT = 5;

    private const DEFAULT_PER_CLIENT_HINT_WINDOW = 60;

    public function __construct(
        private readonly ClientAuthenticator $clientAuth,
        private readonly BackchannelAuthentication $ciba,
        private readonly DynamicGrantPolicy $dynamicGrants,
        private readonly AudienceResolver $audiences,
        private readonly CibaClientNotifications $notifications,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        // Client-authenticated like the token endpoint, and CONFIDENTIALLY so.
        //
        // authenticate() lets a public client through on client_id alone, which is safe
        // where a front channel and PKCE bind the flow to the browser that started it.
        // CIBA has neither: there is no redirect, no code_verifier, and the only human
        // check is the approval prompt this endpoint puts on someone's phone. So a public
        // client_id — which is not a secret and travels in every app binary — was enough
        // to spray prompts at arbitrary users via login_hint, and a person who has
        // dismissed thirty of them approves the thirty-first.
        //
        // The one exception is a SELF-REGISTERED public client for a resource whose host
        // explicitly allowed it (`dynamic_public_backchannel`): a CLI that cannot keep a
        // key. It is held to more below — a named resource, a binding message and the same
        // rate limits — and the person sees all of it before approving.
        $client = $this->clientAuth->authenticateConfidential($request);

        if ($client === null) {
            $candidate = $this->clientAuth->authenticate($request);
            $client = $candidate !== null && $candidate->type === ClientType::Public && DynamicGrantPolicy::applies($candidate)
                ? $candidate
                : null;
        }

        if ($client === null) {
            return new JsonResponse(['error' => 'invalid_client'], 401);
        }

        // Enforce the registered grant at INITIATION, not only at redemption: otherwise a
        // client that can never complete this flow still creates its state and puts a
        // prompt in front of a user.
        if (! GrantPolicy::allows($client, 'urn:openid:params:grant-type:ciba')) {
            return new JsonResponse(['error' => 'unauthorized_client'], 400);
        }

        $loginHint = trim($request->string('login_hint')->toString());

        // CIBA Core §7.1: exactly one hint is required to identify the user. We
        // support login_hint; a request with none cannot be fulfilled.
        if ($loginHint === '') {
            return new JsonResponse(['error' => 'invalid_request'], 400);
        }

        $scope = $request->string('scope')->toString();
        $scopes = $scope === '' ? [] : array_values(array_filter(explode(' ', $scope), fn (string $s): bool => $s !== ''));

        // RFC 8707 on the backchannel request: the audience is fixed here, stored with the
        // request and shown to the person, so the token the poll yields is bound to it the
        // way an authorization code's is. A self-registered client must name one its
        // resource opened CIBA on; any client's is checked now rather than after approval,
        // so nobody approves a request that could never become a token.
        try {
            $resource = ResourceParameter::fromRequest($request);
            $declared = $this->dynamicGrants->resourceFor($client, 'urn:openid:params:grant-type:ciba', $resource);

            if ($resource !== null) {
                $this->audiences->resolve($client, $scopes, $resource);
            }
        } catch (InvalidAudience $e) {
            return new JsonResponse(['error' => $e->error, 'error_description' => $e->getMessage()], 400);
        }

        $bindingMessage = $request->string('binding_message')->toString();

        // A self-registered client is anyone who reached the registration endpoint, so the
        // person must be able to tell its prompt from a spoofed one: the client shows a
        // short message (a code is best) in its own window, and the approval shows the same.
        if ($declared !== null && trim($bindingMessage) === '') {
            return new JsonResponse([
                'error' => 'invalid_binding_message',
                'error_description' => 'A self-registered client must send a binding_message the person can match on screen.',
            ], 400);
        }

        // CIBA Core §7.1/§13: a binding message the OP cannot display is
        // `invalid_binding_message`, not a database error. It is shown on a phone beside
        // an Approve button, so it is short by design; the column holds 255.
        if (mb_strlen($bindingMessage) > self::BINDING_MESSAGE_MAX) {
            return new JsonResponse([
                'error' => 'invalid_binding_message',
                'error_description' => 'The binding_message is longer than '.self::BINDING_MESSAGE_MAX.' characters.',
            ], 400);
        }

        // CIBA Core §7.1: a client registered for ping MUST send the bearer token Cbox ID
        // will present at its notification endpoint. Checked before anyone is prompted, so
        // nobody approves a request whose answer could not be delivered. A poll-mode
        // client's token, if it sends one, is ignored: it has nowhere to be used.
        $ping = $client->backchannelTokenDeliveryMode() === BackchannelTokenDeliveryMode::Ping;
        $notificationToken = $ping ? $request->string('client_notification_token')->toString() : '';

        if ($ping && trim($notificationToken) === '') {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'A client registered for ping mode must send a client_notification_token.',
            ], 400);
        }

        if (mb_strlen($notificationToken) > self::CLIENT_NOTIFICATION_TOKEN_MAX) {
            return new JsonResponse([
                'error' => 'invalid_request',
                'error_description' => 'The client_notification_token is longer than '.self::CLIENT_NOTIFICATION_TOKEN_MAX.' characters.',
            ], 400);
        }

        // One client may not keep asking about one person. The key is the hint as sent,
        // lower-cased; the per-person cap in the service catches a client that varies it.
        $key = 'cbox-id:ciba:client:'.$client->client_id.':'.hash('sha256', mb_strtolower($loginHint));
        $limit = self::configInt('cbox-id.oauth.ciba.rate_limits.per_client_hint', self::DEFAULT_PER_CLIENT_HINT);

        if (RateLimiter::tooManyAttempts($key, $limit)) {
            return $this->tooMany(RateLimiter::availableIn($key));
        }

        RateLimiter::hit($key, self::configInt('cbox-id.oauth.ciba.rate_limits.per_client_hint_window', self::DEFAULT_PER_CLIENT_HINT_WINDOW));

        $requestedExpiry = $request->has('requested_expiry') ? $request->integer('requested_expiry') : null;

        // OIDC CIBA Core §7.1: the optional `nonce` binds the eventual id_token to
        // this backchannel request so the client can detect replay. CIBA persists it
        // and the id_token path echoes it — so thread it through here rather than
        // dropping it. A blank/whitespace-only value is treated as absent.
        $nonce = trim($request->string('nonce')->toString());

        try {
            $result = $this->ciba->request(
                $client,
                $scopes,
                $loginHint,
                $bindingMessage !== '' ? $bindingMessage : null,
                $nonce !== '' ? $nonce : null,
                $requestedExpiry,
                $resource,
            );
        } catch (ScopeNotGranted $e) {
            // invalid_scope rather than a quietly narrower grant — see
            // CibaAuthenticationService::request().
            return new JsonResponse([
                'error' => 'invalid_scope',
                'error_description' => $e->getMessage(),
            ], 400);
        } catch (UnknownUserHint) {
            return new JsonResponse([
                'error' => 'unknown_user_id',
                'error_description' => 'login_hint must be a user id or a confirmed email address of a user in this environment.',
            ], 400);
        } catch (CibaRateLimited $e) {
            return $this->tooMany($e->retryAfter);
        }

        if ($ping) {
            $this->notifications->remember($result, $notificationToken);
        }

        // Only the client-facing fields are serialized — never the internal request
        // id the host uses to approve.
        return new JsonResponse([
            'auth_req_id' => $result->authReqId,
            'expires_in' => $result->expiresIn,
            'interval' => $result->interval,
        ]);
    }

    /**
     * Too many requests: 429 with `slow_down` (the CIBA poll's own word for "back off") and
     * when to try again. Nothing was filed and nobody was prompted.
     */
    private function tooMany(int $retryAfter): JsonResponse
    {
        return new JsonResponse([
            'error' => 'slow_down',
            'error_description' => 'Too many backchannel authentication requests. Try again later.',
        ], 429, ['Retry-After' => (string) max(1, $retryAfter)]);
    }

    /** A positive whole number from config, or the default when it is not one. */
    private static function configInt(string $key, int $default): int
    {
        $value = config($key, $default);

        return is_numeric($value) && (int) $value > 0 ? (int) $value : $default;
    }
}
