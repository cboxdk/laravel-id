<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

// The guard is enabled (default) for these tests.
beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => true]));

it('rejects loopback, private, link-local and reserved addresses', function (string $url): void {
    expect(SafeWebhookUrl::isSafe($url))->toBeFalse();
})->with([
    'http://127.0.0.1/hook',
    'http://localhost/hook',
    'http://[::1]/hook',
    'http://169.254.169.254/latest/meta-data/',   // cloud metadata
    'http://10.0.0.5/hook',
    'http://172.16.0.1/hook',
    'http://192.168.1.1/hook',
    'https://user:pass@example.com/hook',          // embedded credentials
    'ftp://example.com/hook',                       // disallowed scheme
    'file:///etc/passwd',
]);

it('allows a public address', function (): void {
    expect(SafeWebhookUrl::isSafe('https://93.184.216.34/hook'))->toBeTrue(); // public IP literal
});

it('refuses to register a webhook that points at a private address', function (): void {
    app(WebhookRegistry::class)->register('org_a', 'http://169.254.169.254/', ['user.created']);
})->throws(UnsafeWebhookUrl::class);
