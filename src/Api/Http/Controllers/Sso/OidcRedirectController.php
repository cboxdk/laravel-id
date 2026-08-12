<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Http\Controllers\Sso;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\OidcRelyingParty;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Support\FederationFlowStash;
use Cbox\Id\Federation\ValueObjects\FederationFlowState;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;

/**
 * `GET /sso/oidc/{connection}/redirect` — begins an OIDC (RP-initiated) login.
 * Generates a `state` (CSRF) and `nonce` (replay defense), stashes them where the
 * callback can read them back — see {@see FederationFlowStash}, which is not simply the
 * session because a provider answering with `form_post` sends a cross-site POST no
 * `SameSite=Lax` session cookie survives — and redirects the browser to the IdP's
 * authorization endpoint.
 */
class OidcRedirectController
{
    public function __construct(
        private readonly Connections $connections,
        private readonly OidcRelyingParty $client,
        private readonly FederationFlowStash $stash,
    ) {}

    public function __invoke(Request $request, string $connection): RedirectResponse|JsonResponse
    {
        $model = $this->connections->byId($connection);

        if ($model === null || ! $model->isActive() || $model->type !== ConnectionType::Oidc) {
            return new JsonResponse(['error' => 'Unknown or inactive OIDC connection.'], 404);
        }

        $flow = FederationFlowState::fresh();

        $this->stash->put($request, $model->id, $flow);

        $redirectUri = url('/sso/oidc/'.$model->id.'/callback');

        return new RedirectResponse(
            $this->client->authorizeUrl($model, $redirectUri, $flow->state, $flow->nonce),
        );
    }
}
