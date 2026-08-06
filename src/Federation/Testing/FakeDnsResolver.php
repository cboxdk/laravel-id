<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Testing;

use Cbox\Id\Federation\Contracts\DnsResolver;

/**
 * An in-memory {@see DnsResolver} for tests: publish TXT records for a host, then
 * assert domain verification succeeds or fails without touching real DNS.
 */
class FakeDnsResolver implements DnsResolver
{
    /** @var array<string, list<string>> */
    private array $records = [];

    public function publish(string $host, string $value): self
    {
        $this->records[$host][] = $value;

        return $this;
    }

    public function txtRecords(string $host): array
    {
        return $this->records[$host] ?? [];
    }
}
