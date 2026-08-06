<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Manifest\SafeManifestUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Provisioning\Support\SafeScimUrl;
use Cbox\Id\Webhooks\Support\SafeWebhookUrl;

/**
 * Turning host verification OFF must not turn redirect chasing ON.
 *
 * The four `verify_url` toggles exist so an on-prem deployment can reach an internal host
 * it genuinely owns — a private SCIM endpoint, an issuer on the same VPC. They were never
 * meant to say "and follow that anywhere it points".
 *
 * But the disabled branch returned a bare `[]`, which is not "no opinion" — it is Guzzle's
 * default, and Guzzle's default chases up to five redirects. So an operator who set the
 * flag to admit one internal issuer also re-enabled redirect following for every outbound
 * fetch on that plane, and a URL the tenant controls could 302 to `169.254.169.254` and
 * be served the instance metadata.
 *
 * `laravel-ssrf`'s own `Guard::pinnedOptions()` refuses redirects unconditionally, and
 * `laravel-siem`'s adapter already mirrored it. These four did not, which is why this is a
 * test rather than an assumption: the ENABLED path was covered everywhere and the disabled
 * one nowhere, so the gap was exactly where nobody was looking.
 */
it('refuses redirects even with verification disabled', function (string $key, callable $options): void {
    config([$key => false]);

    expect($options('https://internal.example/whatever'))
        ->toBe(['allow_redirects' => false], $key.' handed the caller Guzzle\'s redirect default');
})->with([
    'federation' => ['cbox-id.federation.verify_url', fn (string $u) => SafeFederationUrl::pinnedOptions($u)],
    'provisioning' => ['cbox-id.provisioning.verify_url', fn (string $u) => SafeScimUrl::pinnedOptions($u)],
    'webhooks' => ['cbox-id.webhooks.verify_url', fn (string $u) => SafeWebhookUrl::pinnedOptions($u)],
    'manifest' => ['cbox-id.access_control.verify_manifest_url', fn (string $u) => SafeManifestUrl::pinnedOptions($u)],
])->group('security');
