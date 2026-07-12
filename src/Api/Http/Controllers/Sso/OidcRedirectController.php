<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\OidcClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * `GET /sso/oidc/{connection}/redirect` — begins an OIDC (RP-initiated) login.
 * Generates a `state` (CSRF) and `nonce` (replay defense), stashes them in the
 * session, and redirects the browser to the IdP's authorization endpoint.
 */
final class OidcRedirectController
{
    public function __construct(
        private readonly Connections $connections,
        private readonly OidcClient $client,
    ) {}

    public function __invoke(Request $request, string $connection): RedirectResponse|JsonResponse
    {
        $model = $this->connections->byId($connection);

        if ($model === null || ! $model->isActive() || $model->type !== ConnectionType::Oidc) {
            return new JsonResponse(['error' => 'Unknown or inactive OIDC connection.'], 404);
        }

        $state = bin2hex(random_bytes(16));
        $nonce = bin2hex(random_bytes(16));

        $request->session()->put('oidc.'.$model->id, ['state' => $state, 'nonce' => $nonce]);

        $redirectUri = url('/sso/oidc/'.$model->id.'/callback');

        return new RedirectResponse($this->client->authorizeUrl($model, $redirectUri, $state, $nonce));
    }
}
