<?php

declare(strict_types=1);

namespace Cbox\Id\Federation\Contracts;

/**
 * Reads DNS TXT records for a host. Behind a contract so domain-verification
 * logic is testable against fixed records (a real network lookup is neither
 * deterministic nor available in CI) and so a host can swap the resolver.
 */
interface DnsResolver
{
    /**
     * The TXT record strings published at the given host (empty if none / lookup
     * fails). Each returned string is one record's concatenated value.
     *
     * @return list<string>
     */
    public function txtRecords(string $host): array;
}
