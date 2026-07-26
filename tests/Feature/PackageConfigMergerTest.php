<?php

declare(strict_types=1);

use Cbox\Id\Support\PackageConfigMerger;

it('fills in a nested package default the host did not restate', function (): void {
    // The exact shape of a host that publishes a partial config: it names ONE key
    // under `oauth`. Under the framework's shallow mergeConfigFrom this deleted
    // every other `oauth` default outright.
    $merged = PackageConfigMerger::merge(
        defaults: [
            'oauth' => [
                'access_token_ttl' => 900,
                'require_par' => false,
                'ciba' => ['ttl_seconds' => 300, 'poll_interval' => 5],
            ],
        ],
        host: [
            'oauth' => ['authorization_endpoint_path' => '/oauth/authorize'],
        ],
    );

    expect($merged['oauth'])->toBe([
        'authorization_endpoint_path' => '/oauth/authorize',
        'access_token_ttl' => 900,
        'require_par' => false,
        'ciba' => ['ttl_seconds' => 300, 'poll_interval' => 5],
    ]);
});

it('lets the host win on every leaf key it defines, including falsy ones', function (): void {
    $merged = PackageConfigMerger::merge(
        defaults: ['oauth' => ['require_par' => false, 'embed_entitlements' => true, 'access_token_ttl' => 900]],
        host: ['oauth' => ['require_par' => true, 'embed_entitlements' => false, 'access_token_ttl' => 0]],
    );

    expect($merged['oauth'])->toBe(['require_par' => true, 'embed_entitlements' => false, 'access_token_ttl' => 0]);
});

it('replaces a host list instead of concatenating, so a host can SHRINK a default list', function (): void {
    // The trap this rule exists to avoid: appending would graft `profile` and
    // `email` back onto a host that deliberately narrowed the list.
    $merged = PackageConfigMerger::merge(
        defaults: ['oauth' => ['allowed_scopes' => ['openid', 'profile', 'email']]],
        host: ['oauth' => ['allowed_scopes' => ['openid']]],
    );

    expect($merged['oauth']['allowed_scopes'])->toBe(['openid']);
});

it('lets a host empty a default list entirely', function (): void {
    $merged = PackageConfigMerger::merge(
        defaults: ['api' => ['middleware' => ['throttle:api']]],
        host: ['api' => ['middleware' => []]],
    );

    expect($merged['api']['middleware'])->toBe([]);
});

it('does not merge across a type change — the host value stands', function (): void {
    expect(PackageConfigMerger::merge(['a' => ['x' => 1]], ['a' => 'scalar']))->toBe(['a' => 'scalar'])
        ->and(PackageConfigMerger::merge(['a' => 'scalar'], ['a' => ['x' => 1]]))->toBe(['a' => ['x' => 1]]);
});

it('exposes every package default through config() once the provider has registered', function (): void {
    $defaults = require __DIR__.'/../../config/cbox-id.php';

    /** @var array<string, mixed> $defaults */
    foreach (array_keys($defaults) as $key) {
        expect(config()->has('cbox-id.'.$key))->toBeTrue("cbox-id.{$key} is unreachable");
    }

    expect(config('cbox-id.oauth.access_token_ttl'))->toBe(900)
        ->and(config('cbox-id.oauth.decisions.max_batch'))->toBe(50)
        ->and(config('cbox-id.oauth.ciba.ttl_seconds'))->toBe(300)
        ->and(config('cbox-id.oauth.dynamic_registration.mode'))->toBe('disabled')
        ->and(config('cbox-id.oauth.require_par'))->toBeFalse()
        ->and(config('cbox-id.webauthn.user_verification'))->toBeTrue();
});
