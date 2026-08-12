<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Manifest\SafeManifestUrl;
use Cbox\Id\Federation\Support\SafeFederationUrl;
use Cbox\Id\Migration\Support\SafeLegacyLoginUrl;
use Cbox\Id\Provisioning\Support\SafeScimUrl;
use Cbox\Id\Webhooks\Exceptions\UnsafeWebhookUrl;
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
    // The fifth plane, added late and the most exposed of the five: this is the only
    // outbound request in the package whose body is a live plaintext password, and it was
    // the one still deciding the toggle inline instead of through a `Safe*Url`.
    'legacy login' => ['cbox-id.migration.verify_url', fn (string $u) => SafeLegacyLoginUrl::pinnedOptions($u)],
])->group('security');

/**
 * AND THE TOGGLE ITSELF MUST BE READ THE WAY AN OPERATOR WRITES IT.
 *
 * Every one of these planes used to compare `config(...) !== true`. `=1` and `=on` in an
 * env file arrive as strings, neither is `true`, and the guard turned itself OFF — the
 * opposite of what was written, on the only setting in the file whose failure direction
 * is "outbound requests may now reach the metadata service".
 */
it('keeps verification on for every truthy way an operator writes it', function (mixed $value): void {
    config(['cbox-id.webhooks.verify_url' => $value]);

    // The guard being ON is what makes an unresolvable host throw. Switched off, this
    // returns quietly — so the exception IS the assertion that the toggle was read the
    // way it was written.
    expect(fn (): array => SafeWebhookUrl::pinnedOptions('https://internal.example/whatever'))
        ->toThrow(UnsafeWebhookUrl::class);
})->with(['1', 'true', 'on', 'yes', 1, true, 'nonsense'])->group('security');

it('switches verification off only for a recognizably false value', function (mixed $value): void {
    config(['cbox-id.webhooks.verify_url' => $value]);

    expect(SafeWebhookUrl::pinnedOptions('https://internal.example/whatever'))
        ->toBe(['allow_redirects' => false]);
})->with(['0', 'false', 'off', 'no', 0, false])->group('security');
