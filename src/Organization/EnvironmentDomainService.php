<?php

declare(strict_types=1);

namespace Cbox\Id\Organization;

use Cbox\Id\Federation\Contracts\DnsResolver;
use Cbox\Id\Organization\Contracts\EnvironmentDomains;
use Cbox\Id\Organization\Exceptions\InvalidCustomDomain;
use Cbox\Id\Organization\Models\Environment;
use Cbox\Id\Organization\ValueObjects\DomainChallenge;

/**
 * Self-serve environment custom-domain verification, backed by the environment's
 * `settings` JSON (no migration) and the shared {@see DnsResolver}. The pending
 * challenge lives under `settings.custom_domain` until its TXT record verifies; on
 * success the domain is promoted to the `domain` column (the issuer host) and the
 * pending state cleared. TLS is out of scope by design — see {@see EnvironmentDomains}.
 */
final class EnvironmentDomainService implements EnvironmentDomains
{
    private const SETTINGS_KEY = 'custom_domain';

    /** The TXT record is published at this subdomain of the custom domain. */
    private const CHALLENGE_PREFIX = '_cbox-id-challenge';

    /** The TXT value carries this prefix so the record is unambiguous among others. */
    private const VALUE_PREFIX = 'cbox-id-domain-verification=';

    public function __construct(private readonly DnsResolver $dns) {}

    public function challenge(string $environmentKey): ?DomainChallenge
    {
        $environment = $this->environment($environmentKey);
        $pending = $this->pending($environment);

        if ($pending === null) {
            return null;
        }

        return $this->toChallenge($pending['domain'], $pending['token'], verified: false);
    }

    public function request(string $environmentKey, string $domain): DomainChallenge
    {
        $domain = $this->normalize($domain);
        $this->assertUsable($domain, $environmentKey);

        $environment = $this->environment($environmentKey);
        $token = bin2hex(random_bytes(16));

        $settings = $environment->settings;
        $settings[self::SETTINGS_KEY] = ['domain' => $domain, 'token' => $token];
        $environment->settings = $settings;
        $environment->save();

        return $this->toChallenge($domain, $token, verified: false);
    }

    public function verify(string $environmentKey): DomainChallenge
    {
        $environment = $this->environment($environmentKey);
        $pending = $this->pending($environment);

        if ($pending === null) {
            throw InvalidCustomDomain::malformed('(no pending custom domain to verify)');
        }

        $expected = self::VALUE_PREFIX.$pending['token'];
        $records = array_map('trim', $this->dns->txtRecords(self::CHALLENGE_PREFIX.'.'.$pending['domain']));

        if (! in_array($expected, $records, true)) {
            return $this->toChallenge($pending['domain'], $pending['token'], verified: false);
        }

        // Re-check uniqueness at promotion time (deny-by-default a second time): a
        // race could have let another environment claim the domain since request().
        $this->assertUsable($pending['domain'], $environmentKey);

        $settings = $environment->settings;
        unset($settings[self::SETTINGS_KEY]);
        $environment->settings = $settings;
        $environment->domain = $pending['domain'];
        $environment->save();

        return $this->toChallenge($pending['domain'], $pending['token'], verified: true);
    }

    public function clear(string $environmentKey): void
    {
        $environment = $this->environment($environmentKey);

        $settings = $environment->settings;
        unset($settings[self::SETTINGS_KEY]);
        $environment->settings = $settings;
        $environment->domain = null;
        $environment->save();
    }

    private function toChallenge(string $domain, string $token, bool $verified): DomainChallenge
    {
        return new DomainChallenge(
            domain: $domain,
            recordName: self::CHALLENGE_PREFIX.'.'.$domain,
            recordValue: self::VALUE_PREFIX.$token,
            verified: $verified,
        );
    }

    /**
     * @return array{domain: string, token: string}|null
     */
    private function pending(Environment $environment): ?array
    {
        $pending = $environment->settings[self::SETTINGS_KEY] ?? null;

        if (! is_array($pending) || ! is_string($pending['domain'] ?? null) || ! is_string($pending['token'] ?? null)) {
            return null;
        }

        return ['domain' => $pending['domain'], 'token' => $pending['token']];
    }

    private function environment(string $environmentKey): Environment
    {
        $environment = Environment::query()->find($environmentKey);

        if ($environment === null) {
            throw InvalidCustomDomain::malformed('(unknown environment '.$environmentKey.')');
        }

        return $environment;
    }

    private function normalize(string $domain): string
    {
        return rtrim(strtolower(trim($domain)), '.');
    }

    /**
     * A usable custom domain is a well-formed hostname, not an IP, not a platform
     * base domain (or subdomain of one), and not already claimed by another env.
     */
    private function assertUsable(string $domain, string $environmentKey): void
    {
        if (filter_var($domain, FILTER_VALIDATE_IP) !== false
            || preg_match('/^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/', $domain) !== 1) {
            throw InvalidCustomDomain::malformed($domain);
        }

        foreach ($this->baseDomains() as $base) {
            if ($domain === $base || str_ends_with($domain, '.'.$base)) {
                throw InvalidCustomDomain::reserved($domain);
            }
        }

        $owner = Environment::query()->where('domain', $domain)->value('id');

        if ($owner !== null && $owner !== $environmentKey) {
            throw InvalidCustomDomain::taken($domain);
        }
    }

    /**
     * @return list<string>
     */
    private function baseDomains(): array
    {
        $bases = config('cbox-id.environments.base_domains', []);

        if (! is_array($bases)) {
            return [];
        }

        return array_values(array_filter(
            array_map(fn (mixed $base): string => is_string($base) ? strtolower(trim($base)) : '', $bases),
            fn (string $base): bool => $base !== '',
        ));
    }
}
