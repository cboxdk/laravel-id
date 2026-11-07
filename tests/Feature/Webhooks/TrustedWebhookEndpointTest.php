<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Cbox\Id\Webhooks\Support\TrustedWebhookEndpoint;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\TransferStats;

it('allows only the exact operator endpoint and pins its connection without redirects or proxies', function (): void {
    $url = 'https://signals.internal/cbox-id/webhooks';
    config(['cbox-id.webhooks.verify_url' => true, 'cbox-id.webhooks.trusted_endpoints' => [$url => '127.0.0.1']]);
    SafeWebhookUrl::assert($url);
    $options = SafeWebhookUrl::pinnedOptions($url);
    expect($options['allow_redirects'])->toBeFalse()->and($options['proxy'])->toBe('')
        ->and($options['curl'][CURLOPT_RESOLVE])->toBe(['signals.internal:443:127.0.0.1']);
    ($options['on_stats'])(new TransferStats(new Request('POST', $url), null, 0.1, null, ['primary_ip' => '127.0.0.1']));
    expect(fn () => ($options['on_stats'])(new TransferStats(new Request('POST', $url), null, 0.1, null, ['primary_ip' => '169.254.169.254'])))->toThrow(UnsafeWebhookUrl::class);
    expect(fn () => SafeWebhookUrl::assert('https://signals.internal/admin'))->toThrow(UnsafeWebhookUrl::class);
    expect(TrustedWebhookEndpoint::options($url.'?target=admin'))->toBeNull();
});

it('refuses malformed operator pins rather than falling back to unrestricted networking', function (): void {
    config(['cbox-id.webhooks.trusted_endpoints' => ['http://signals.internal/webhook' => '127.0.0.1']]);
    expect(fn () => SafeWebhookUrl::assert('http://signals.internal/webhook'))->toThrow(UnsafeWebhookUrl::class);
    config(['cbox-id.webhooks.trusted_endpoints' => ['https://signals.internal/webhook' => 'not-an-ip']]);
    expect(fn () => SafeWebhookUrl::assert('https://signals.internal/webhook'))->toThrow(UnsafeWebhookUrl::class);
});
