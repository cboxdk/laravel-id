<?php

declare(strict_types=1);

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\Exceptions\UnusableOrigin;
use Cbox\Id\FrontendApi\Models\PublishableKey;
use Cbox\Id\FrontendApi\Support\Origin;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * NORMALIZATION HAPPENS ONCE, ON THE WAY IN, and request time is never lenient.
 *
 * A browser sends a serialized origin: lowercase scheme and host, port only when it is
 * not the scheme's default, no path, no trailing slash. A person types something else.
 * If both sides are not written identically the allow-list silently fails to match — and
 * the fix somebody reaches for is a looser comparison at request time, which is the
 * vulnerability.
 */
it('writes what a browser would send', function (string $typed, string $expected): void {
    expect(Origin::normalize($typed))->toBe($expected);
})->with([
    'as sent' => ['https://app.acme.com', 'https://app.acme.com'],
    'uppercase host' => ['https://App.Acme.COM', 'https://app.acme.com'],
    'trailing slash' => ['https://app.acme.com/', 'https://app.acme.com'],
    'default port stated' => ['https://app.acme.com:443', 'https://app.acme.com'],
    'non-default port kept' => ['https://app.acme.com:8443', 'https://app.acme.com:8443'],
    'loopback with port' => ['http://localhost:3000', 'http://localhost:3000'],
]);

it('refuses what could never match', function (string $typed): void {
    expect(Origin::normalize($typed))->toBeNull();
})->with([
    'no scheme' => ['acme.com'],
    'a path' => ['https://acme.com/callback'],
    'a wildcard' => ['https://*.acme.com'],
    'the null origin' => ['null'],
    'credentials in the url' => ['https://user:pass@acme.com'],
    'a non-web scheme' => ['ftp://acme.com'],
    'a newline, which would inject a header' => ["https://acme.com\r\nX-Evil: 1"],
    'empty' => [''],
]);

/**
 * Plain `http` is refused away from loopback. A key travelling in the clear can be lifted
 * by anyone on the path — and the entire safety of publishing the key rests on it being
 * useless except from an origin somebody deliberately named.
 */
it('refuses insecure origins, except where a browser trusts them', function (): void {
    $keys = app(PublishableKeys::class);

    expect(fn () => $keys->issue('k', KeyMode::Test, ['http://app.acme.com']))
        ->toThrow(UnusableOrigin::class);

    // Development happens here, and it is the one place a browser treats an insecure
    // origin as trustworthy. Refusing it would mean the first thing a developer meets is
    // an error they cannot fix.
    expect($keys->issue('k', KeyMode::Test, ['http://localhost:3000'])->origins)->toHaveCount(1);
});

/**
 * A dropped entry leaves somebody holding a key that does not work, with no reason why.
 */
it('refuses the whole list rather than silently dropping an entry', function (): void {
    expect(fn () => app(PublishableKeys::class)->issue('k', KeyMode::Test, [
        'https://good.acme.test',
        'not-an-origin',
    ]))->toThrow(UnusableOrigin::class);

    expect(PublishableKey::query()->count())->toBe(0);
});

it('mints a key whose mode is legible in the key itself', function (): void {
    $keys = app(PublishableKeys::class);

    expect($keys->issue('t', KeyMode::Test, ['https://a.test'])->key)->toStartWith('pk_test_')
        ->and($keys->issue('l', KeyMode::Live, ['https://a.test'])->key)->toStartWith('pk_live_');
});
