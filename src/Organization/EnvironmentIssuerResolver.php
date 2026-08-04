<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Identity\EnvironmentRelyingParties;
use Cbox\Id\Kernel\Runtime\RequestLifetime;
use Cbox\Id\Kernel\Tenancy\Concerns\ResolvesEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\OAuthServer\ClientAssertion\ClientAssertionValidator;
use Cbox\Id\OAuthServer\JwtTokenIssuer;
use Cbox\Id\Organization\Models\Environment;

/**
 * Resolves an environment's canonical issuer from its host: a custom domain when set,
 * else `{slug}.{base_domain}`, else the configured platform issuer. The platform-root
 * (is_default) environment and any deployment with no base domains (single-tenant /
 * on-prem) keep the configured `cbox-id.issuer`, so their published identity is
 * unchanged; only tenant environments get their own per-subdomain issuer.
 *
 * Resolutions are memoized FOR THE REQUEST so repeated token minting / metadata reads
 * cost at most one Environment lookup per key. The binding is a singleton, which is a
 * longer life than that — see {@see rememberedThisRequest()} for how the two are
 * reconciled, and for why the obvious fix is the wrong one.
 */
class EnvironmentIssuerResolver implements IssuerResolver
{
    // Lazy per-call resolution of the ambient environment. This class is a `singleton`
    // (OrganizationServiceProvider) and EnvironmentContext is `scoped`, so injecting it here
    // would pin a queue worker to the first job's environment for the life of the process.
    use ResolvesEnvironment;

    /**
     * Memoized per environment. `false` is a resolved answer, not a miss — it records
     * "this environment has no issuer of its own", which is why the memo is read with
     * `array_key_exists` rather than `??=`.
     *
     * @var array<string, string|false>
     */
    private array $own = [];

    private ?RequestLifetime $memoLifetime = null;

    public function issuer(): string
    {
        $key = $this->environments()->current()?->environmentKey();

        return $key !== null ? $this->forEnvironment($key) : $this->fallback();
    }

    public function forEnvironment(string $environmentKey): string
    {
        $own = $this->own($environmentKey);

        return $own === false ? $this->fallback() : $own;
    }

    public function canonicalHost(): ?string
    {
        $key = $this->environments()->current()?->environmentKey();
        $own = $key === null ? false : $this->own($key);

        if ($own === false) {
            // Inheriting the configured issuer means no host is canonical — see the
            // contract. Returning the configured issuer's host here instead would send
            // every health probe, internal LB name and second ingress on a redirect to
            // the public apex.
            return null;
        }

        $host = parse_url($own, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : null;
    }

    /**
     * The environment's OWN issuer — the host it, and only it, answers as — or false
     * when it has none and inherits the deployment-wide configured one.
     */
    private function own(string $environmentKey): string|false
    {
        $memo = $this->rememberedThisRequest();

        if (array_key_exists($environmentKey, $memo)) {
            return $memo[$environmentKey];
        }

        return $this->own[$environmentKey] = $this->resolve($environmentKey);
    }

    /**
     * The memo, emptied if it belongs to an earlier request.
     *
     * The class docblock used to say "memoized per request (the binding is a singleton)",
     * and those two clauses contradict each other: a singleton's life is the PROCESS. On
     * php-fpm the process ends with the request and the contradiction is invisible, which
     * is why it survived — but this package is distributed, and under Octane the memo
     * outlives the fact it recorded. A tenant verifies a custom domain; a warm worker
     * keeps minting tokens with the OLD `iss` while a cold one serves the new one from
     * discovery, so relying-party `iss` validation fails on a fraction of requests, on no
     * pattern anyone can reproduce.
     *
     * REBINDING THIS `scoped` DOES NOT FIX IT, which is worth writing down because it is
     * the obvious one-word edit. {@see EnvironmentRelyingParties},
     * {@see JwtTokenIssuer} and
     * {@see ClientAssertionValidator} are all
     * singletons that constructor-inject this resolver. `forgetScopedInstances()` unsets
     * the BINDING and cannot reach an instance somebody already holds, so the token
     * minting path, the passkey RP path and client authentication would each keep the
     * FIRST request's resolver for the life of the worker — strictly worse, because then
     * the memo is never dropped at all.
     *
     * So the memo is told when the request ended, by whoever holds it. {@see RequestLifetime}
     * is replaced between requests and between queued jobs.
     *
     * @return array<string, string|false>
     */
    private function rememberedThisRequest(): array
    {
        $lifetime = RequestLifetime::current(app());

        if ($this->memoLifetime !== $lifetime) {
            $this->memoLifetime = $lifetime;
            $this->own = [];
        }

        return $this->own;
    }

    private function resolve(string $environmentKey): string|false
    {
        $environment = Environment::query()->find($environmentKey);

        if ($environment === null || $environment->is_default) {
            // Unknown key, or the platform-root apex — keep the configured issuer.
            return false;
        }

        // A custom domain is the ISSUER identity, so trust it ONLY when DNS control
        // was proven ({@see EnvironmentDomainService::verify} stamps domain_verified_at).
        // An unverified domain — one set by a routing/branding path — must never assert
        // an issuer for a host that was not shown to be controlled.
        if (is_string($environment->domain) && $environment->domain !== '' && $environment->domain_verified_at !== null) {
            return 'https://'.$environment->domain;
        }

        $base = $this->baseDomain();

        return $base !== null
            ? 'https://'.$environment->slug.'.'.$base
            : false;
    }

    private function fallback(): string
    {
        $configured = config('cbox-id.issuer');

        if (is_string($configured) && $configured !== '') {
            return rtrim($configured, '/');
        }

        // The fallback MUST be host-independent. `url('/')` reflects the request Host,
        // so an environment whose (unverified) custom domain routed the request here
        // would otherwise publish that very host as its issuer — re-opening the R1
        // identity gap through the back door. app.url is operator-set, not attacker-
        // controllable, so it is the safe deployment default.
        $appUrl = config('app.url');

        return is_string($appUrl) && $appUrl !== '' ? rtrim($appUrl, '/') : 'http://localhost';
    }

    private function baseDomain(): ?string
    {
        $bases = config('cbox-id.environments.base_domains', []);

        return is_array($bases) && isset($bases[0]) && is_string($bases[0]) && $bases[0] !== ''
            ? $bases[0]
            : null;
    }
}
