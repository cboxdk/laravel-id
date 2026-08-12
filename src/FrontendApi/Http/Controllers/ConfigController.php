<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Http\Controllers;

use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\FrontendApi\Contracts\FrontendConfigContributor;
use Cbox\Id\FrontendApi\Models\PublishableKey;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * Everything a browser needs to draw a sign-in box, and nothing that identifies anybody.
 *
 * THIS IS THE DOCUMENT THAT MAKES EMBEDDED UI POSSIBLE. Until now an SDK component could
 * not render a themed form, because finding out what to render — which methods are on,
 * which social buttons to show, what the customer's colours are — required a server
 * holding a client secret. So the components redirected instead, and the redirect is the
 * gap against every competitor's embedded experience.
 *
 * WHAT MAY BE HERE. Only facts that are already public to anyone who visits the hosted
 * sign-in page: the endpoints, the enabled methods, the social buttons, the branding. A
 * person can read all of it by viewing source on the hosted page today; putting it behind
 * an API changes who can render it, not who can know it.
 *
 * WHAT MAY NEVER BE HERE, and the reason each is a real temptation:
 *
 *  - Anything keyed on an email or user id. "Does this account exist" is the enumeration
 *    oracle every identity product eventually leaks, and a public endpoint is the easiest
 *    place to leak it. Method discovery per user belongs behind an authenticated flow.
 *  - Counts, names or ids of organizations, users or connections beyond what a sign-in
 *    button needs. A competitor with a publishable key should learn nothing about the
 *    size or shape of the customer's estate.
 *  - Anything an operator configured privately: webhook URLs, SCIM state, internal
 *    connection config. It is one array merge away and it must not be.
 *
 * Cached in the browser for a minute. Long enough that a multi-component page fetches it
 * once, short enough that flipping a provider on shows up while somebody is still looking
 * at the console.
 */
class ConfigController
{
    /** @param iterable<FrontendConfigContributor> $contributors */
    public function __construct(private readonly iterable $contributors = []) {}

    public function __invoke(Request $request): JsonResponse
    {
        $key = $request->attributes->get('cbox_publishable_key');

        $config = [
            'mode' => $key instanceof PublishableKey ? $key->mode->value : null,
            'issuer' => url('/'),
            'endpoints' => [
                'authorization' => url('/oauth/authorize'),
                'token' => url('/oauth/token'),
                'userinfo' => url('/oauth/userinfo'),
                'end_session' => url('/oauth/logout'),
                'jwks' => url('/.well-known/jwks.json'),
            ],
            'social' => $this->socialButtons(),
        ];

        foreach ($this->contributors as $contributor) {
            // THE FRAMEWORK'S OWN KEYS WIN, always. A contributor is host code and is
            // trusted to add, not to redefine: one returning its own `issuer` or
            // `endpoints` would point every embedded sign-in box somewhere else, and the
            // contract's promise that a contributor "adds to the document" would be a
            // docblock rather than a rule. The union operator makes it a rule.
            $config = $config + $contributor->contribute($config);
        }

        return new JsonResponse($config)
            // `private`, because the document differs per environment and a shared cache
            // keyed only on the URL would serve one customer's branding to another's page.
            ->header('Cache-Control', 'private, max-age=60');
    }

    /**
     * The social sign-in buttons to draw.
     *
     * Name and provider only — never the connection's id, and never its config. The id is
     * an internal handle a page has no use for, and the config is secret by definition.
     * A button needs a label and something to POST to, and that is what this gives.
     *
     * @return list<array{provider: string, name: string}>
     */
    private function socialButtons(): array
    {
        /** @var list<array{provider: string, name: string}> $buttons */
        $buttons = Connection::query()
            ->where('status', ConnectionStatus::Active->value)
            ->whereNotNull('provider')
            ->orderBy('name')
            ->get(['provider', 'name'])
            ->map(static fn (Connection $c): array => [
                'provider' => (string) $c->provider,
                'name' => $c->name,
            ])
            ->values()
            ->all();

        return $buttons;
    }
}
