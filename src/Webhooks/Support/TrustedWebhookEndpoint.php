<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use GuzzleHttp\TransferStats;

/** Operator-owned exact endpoint pins, separate from customer-controlled URLs. */
final class TrustedWebhookEndpoint
{
    /** @return array<string, mixed>|null */
    public static function options(string $url): ?array
    {
        $endpoints = config('cbox-id.webhooks.trusted_endpoints', []);
        if (! is_array($endpoints) || ! array_key_exists($url, $endpoints)) {
            return null;
        }
        $ip = $endpoints[$url];
        $parts = parse_url($url);
        if (! is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false || $parts === false
            || ($parts['scheme'] ?? '') !== 'https' || ! isset($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || ! defined('CURLOPT_RESOLVE')) {
            throw UnsafeWebhookUrl::make('invalid operator-owned webhook endpoint pin');
        }
        $host = $parts['host'];
        $port = $parts['port'] ?? 443;
        $address = str_contains($ip, ':') ? '['.$ip.']' : $ip;

        return [
            'allow_redirects' => false,
            'proxy' => '',
            'curl' => [CURLOPT_RESOLVE => [$host.':'.$port.':'.$address]],
            'on_stats' => static function (TransferStats $stats) use ($ip): void {
                $connected = $stats->getHandlerStats()['primary_ip'] ?? null;
                if (! is_string($connected) || inet_pton($connected) !== inet_pton($ip)) {
                    throw UnsafeWebhookUrl::make('webhook connection did not use the operator-pinned address');
                }
            },
        ];
    }
}
