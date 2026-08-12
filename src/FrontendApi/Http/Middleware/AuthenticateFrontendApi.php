<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi\Http\Middleware;

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Models\PublishableKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

/**
 * The whole door to the Frontend API: which key, from which origin, how often.
 *
 * ONE MIDDLEWARE ON PURPOSE. Key resolution, origin matching and CORS are three views of
 * a single decision — may THIS page talk to us — and splitting them across three classes
 * is how a request ends up passing two of the three. In particular the CORS headers must
 * be emitted by the code that decided the origin was allowed, never by a generic CORS
 * layer reading a config list, because two allow-lists is one too many.
 *
 * THE ORDER MATTERS AND IS DELIBERATE:
 *
 *  1. Preflight is answered FIRST and ON THE ORIGIN ALONE. This is not a shortcut, it is
 *     the only thing that works: a browser preflight carries no custom headers — it
 *     advertises their names in `Access-Control-Request-Headers` and sends the values on
 *     the real request — so requiring the key here refuses the OPTIONS, and the browser
 *     never sends the POST. A preflight grants nothing; the real request still has to
 *     present a key that names this origin.
 *  2. Then key, then origin, for every real request. A missing key is a client that has
 *     not been configured; a bad origin is a key being used from somewhere its owner did
 *     not name.
 *  3. Rate limiting AFTER both, keyed by the key. Limiting before identification means
 *     one abusive caller exhausts a bucket shared with every legitimate one.
 *
 * WHAT THIS DOOR IS NOT. It grants no authority. Everything behind it is either public by
 * nature (how do I theme the sign-in box) or gated by a session cookie the browser
 * already had. The key names an environment and says "a browser is asking" — the origin
 * allow-list is what makes a public string safe to publish.
 */
class AuthenticateFrontendApi
{
    /** Where a browser presents the key. A header, never a query string — see below. */
    private const HEADER = 'X-Cbox-Publishable-Key';

    /**
     * Requests per minute per key.
     *
     * Generous, because a single page load legitimately makes several of these and a
     * customer's whole traffic shares one key. It is a ceiling against loops and scraping,
     * not a quota — a quota belongs in billing, where somebody can see it.
     */
    private const PER_MINUTE = 600;

    public function __construct(
        private readonly PublishableKeys $keys,
        private readonly EnvironmentContext $environments,
    ) {}

    /**
     * @param  Closure(Request): Response  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $origin = (string) $request->headers->get('Origin', '');

        // Answered before the key is even looked for — see the ordering note above.
        if ($request->getMethod() === 'OPTIONS') {
            return $this->keys->allowsOrigin($origin)
                ? $this->cors(new Response('', 204), $origin)
                : $this->refuse('unauthorized', 'That origin is not on any active key\'s allow-list.', 401);
        }

        $key = $this->presentedKey($request);

        if ($key === null) {
            return $this->refuse('missing_key', 'No publishable key was presented.', 401);
        }

        $resolved = $this->keys->resolve($key);

        if (! $resolved instanceof PublishableKey) {
            // Deliberately the same shape as a bad origin below. Telling an anonymous
            // caller "that key exists but not from here" confirms the key.
            return $this->refuse('unauthorized', 'That publishable key cannot be used from this origin.', 401);
        }

        if (! $resolved->allowsOrigin($origin)) {
            return $this->refuse('unauthorized', 'That publishable key cannot be used from this origin.', 401);
        }

        $limiterKey = 'cbox-frontend-api:'.$resolved->id;

        if (RateLimiter::tooManyAttempts($limiterKey, self::PER_MINUTE)) {
            $response = $this->refuse('rate_limited', 'Too many requests.', 429);
            $response->headers->set('Retry-After', (string) RateLimiter::availableIn($limiterKey));

            return $response;
        }

        RateLimiter::hit($limiterKey);

        return $this->environments->runAs(
            GenericEnvironment::of($resolved->environment_id),
            function () use ($request, $next, $resolved, $origin): Response {
                $request->attributes->set('cbox_publishable_key', $resolved);

                $this->touch($resolved);

                return $this->cors($next($request), $origin);
            },
        );
    }

    /**
     * The key off the request.
     *
     * A HEADER ONLY. A query string would put the key in server logs, in `Referer` on
     * every outbound link, and in browser history — and while the key is public, spraying
     * it across logs makes revocation harder to reason about and makes the key look like
     * a secret that leaked. `Authorization: Bearer` is deliberately not used either: it
     * would collide with the access token a page may also be sending.
     */
    private function presentedKey(Request $request): ?string
    {
        $header = $request->headers->get(self::HEADER);

        return is_string($header) && $header !== '' ? $header : null;
    }

    /**
     * Record that the key was used, at most once a minute.
     *
     * "Last used" is what tells an operator whether a key in the console is still wired
     * into something before they revoke it. Writing it on every request would be a write
     * per page load for a column nobody reads in real time.
     */
    private function touch(PublishableKey $key): void
    {
        if ($key->last_used_at !== null && $key->last_used_at->diffInSeconds(now()) < 60) {
            return;
        }

        PublishableKey::query()->whereKey($key->id)->update(['last_used_at' => now()]);
    }

    /**
     * CORS headers for an origin already proven to be on the key's allow-list.
     *
     * `Vary` NAMES BOTH HEADERS THE ANSWER DEPENDS ON, and the key is the one that was
     * missing. The middleware picks the ENVIRONMENT from the key rather than from the
     * host, so one URL, one origin and two keys are two different documents — and a
     * browser cache keyed on the URL alone would serve environment A's configuration to a
     * page holding environment B's key. `private` keeps shared caches out of it; the
     * browser's own cache is the one that needed telling.
     *
     * `Vary: Origin` is not optional either: without it a shared cache can hand one customer's
     * `Access-Control-Allow-Origin` to another customer's browser, and the second one is
     * refused for reasons nobody can reproduce.
     *
     * `Allow-Credentials` is true because the session endpoint reads the browser's own
     * cookie — which is exactly why the allow-list may never contain a wildcard, and why
     * the echoed origin is the one we matched rather than the one we were sent.
     */
    private function cors(Response $response, string $origin): Response
    {
        $response->headers->set('Access-Control-Allow-Origin', $origin);
        $response->headers->set('Access-Control-Allow-Credentials', 'true');
        // `Authorization` is here because `/frontend/v1/session` reads a bearer token the
        // page already holds; without it that endpoint is unusable cross-origin no matter
        // what the preflight answers.
        $response->headers->set('Access-Control-Allow-Headers', self::HEADER.', Authorization, Content-Type, Accept');
        $response->headers->set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        $response->headers->set('Access-Control-Max-Age', '600');
        // Appended, not set: a controller may already have varied on something of its own,
        // and clobbering that would be a caching bug introduced by the CORS layer.
        $vary = array_filter(array_map(trim(...), explode(',', (string) $response->headers->get('Vary', ''))));

        $response->headers->set('Vary', implode(', ', array_unique([...$vary, 'Origin', self::HEADER])));

        return $response;
    }

    /**
     * A refusal, WITHOUT CORS headers.
     *
     * That is the point rather than an omission: a browser that is refused should see a
     * CORS failure, because the page has no business reading the body of a rejection it
     * was not authorized to make. The developer sees the real reason in devtools' network
     * tab and in our logs; the page sees nothing it could branch on.
     */
    private function refuse(string $code, string $message, int $status): Response
    {
        return new JsonResponse(['error' => $code, 'error_description' => $message], $status);
    }
}
