<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Organization\Models\Environment;

/**
 * Resolves an environment's canonical issuer from its host: a custom domain when set,
 * else `{slug}.{base_domain}`, else the configured platform issuer. The platform-root
 * (is_default) environment and any deployment with no base domains (single-tenant /
 * on-prem) keep the configured `cbox-id.issuer`, so their published identity is
 * unchanged; only tenant environments get their own per-subdomain issuer.
 *
 * Resolutions are memoized per request (the binding is a singleton) so repeated token
 * minting / metadata reads cost at most one Environment lookup per key.
 */
class EnvironmentIssuerResolver implements IssuerResolver
{
    /** @var array<string, string> */
    private array $cache = [];

    public function __construct(private readonly EnvironmentContext $environments) {}

    public function issuer(): string
    {
        $key = $this->environments->current()?->environmentKey();

        return $key !== null ? $this->forEnvironment($key) : $this->fallback();
    }

    public function forEnvironment(string $environmentKey): string
    {
        return $this->cache[$environmentKey] ??= $this->resolve($environmentKey);
    }

    private function resolve(string $environmentKey): string
    {
        $environment = Environment::query()->find($environmentKey);

        if ($environment === null || $environment->is_default) {
            // Unknown key, or the platform-root apex — keep the configured issuer.
            return $this->fallback();
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
            : $this->fallback();
    }

    private function fallback(): string
    {
        $configured = config('cbox-id.issuer');

        return is_string($configured) && $configured !== ''
            ? rtrim($configured, '/')
            : rtrim(url('/'), '/');
    }

    private function baseDomain(): ?string
    {
        $bases = config('cbox-id.environments.base_domains', []);

        return is_array($bases) && isset($bases[0]) && is_string($bases[0]) && $bases[0] !== ''
            ? $bases[0]
            : null;
    }
}
