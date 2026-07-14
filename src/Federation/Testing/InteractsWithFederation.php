<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Testing;

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\DnsResolver;
use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\Models\VerifiedDomain;

trait InteractsWithFederation
{
    /**
     * @param  array<string, mixed>  $config
     */
    protected function makeConnection(
        string $organizationId,
        ConnectionType $type = ConnectionType::Saml,
        string $name = 'Okta',
        array $config = [],
        bool $active = true,
    ): Connection {
        $connections = app(Connections::class);
        $connection = $connections->create($organizationId, $type, $name, $config);

        if ($active) {
            $connections->activate($organizationId, $connection->id);
        }

        return $connection->refresh();
    }

    /**
     * Swap the DNS resolver for an in-memory fake and return it, so a test can
     * publish TXT records before verifying a domain.
     */
    protected function fakeDns(): FakeDnsResolver
    {
        $current = app(DnsResolver::class);

        if ($current instanceof FakeDnsResolver) {
            return $current;
        }

        $fake = new FakeDnsResolver;
        app()->instance(DnsResolver::class, $fake);
        // The DomainVerification singleton was built with the real resolver;
        // forget it so the next resolve rebuilds it against the fake.
        app()->forgetInstance(DomainVerification::class);

        return $fake;
    }

    /**
     * Register a domain and, by default, verify it by publishing the challenge to
     * the fake resolver — the common "org already proved this domain" setup.
     */
    protected function makeVerifiedDomain(string $organizationId, string $domain, bool $verified = true): VerifiedDomain
    {
        // Fake DNS BEFORE resolving the service, so the resolver it is built with
        // is the fake (the service is a singleton captured at first resolve).
        $dns = $verified ? $this->fakeDns() : null;
        $domains = app(DomainVerification::class);
        $record = $domains->add($organizationId, $domain);

        if ($dns !== null) {
            $dns->publish($domains->challengeHost($domain), $record->verification_token);
            $domains->verify($record->id);
        }

        return $record->refresh();
    }
}
