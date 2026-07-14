<?php

declare(strict_types=1);

namespace Cbox\Id\Federation;

use Cbox\Id\Federation\Contracts\DnsResolver;

/**
 * The production DNS resolver — a thin wrapper over PHP's `dns_get_record`.
 * Failures (NXDOMAIN, timeouts) return no records rather than throwing, so a
 * missing challenge record simply reads as "not verified".
 */
final class SystemDnsResolver implements DnsResolver
{
    public function txtRecords(string $host): array
    {
        $records = @dns_get_record($host, DNS_TXT);

        if ($records === false) {
            return [];
        }

        $out = [];

        foreach ($records as $record) {
            // `dns_get_record` exposes the value as `txt`, and long records split
            // across `entries`; collect whatever is present.
            if (isset($record['txt']) && is_string($record['txt'])) {
                $out[] = $record['txt'];
            }

            if (isset($record['entries']) && is_array($record['entries'])) {
                foreach ($record['entries'] as $entry) {
                    if (is_string($entry)) {
                        $out[] = $entry;
                    }
                }
            }
        }

        return $out;
    }
}
