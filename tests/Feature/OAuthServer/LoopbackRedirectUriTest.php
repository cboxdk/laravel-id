<?php

declare(strict_types=1);

use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Support\WebRedirectUri;
use Cbox\Id\OAuthServer\ValueObjects\AuthorizationClient;

/*
 * The loopback port exception (RFC 8252 §7.3) reads a redirect URI with parse_url(), and
 * parse_url() and a browser's URL parser do not agree on every authority. The exception
 * may only be reached by a URI both read the same way: http, a loopback host, no
 * credentials, no fragment, no backslash, whitespace or control character, and nothing a
 * rebuild from its own parse would change. Anything else is held to an exact match.
 */

function loopbackClient(array $redirectUris): AuthorizationClient
{
    return AuthorizationClient::registered((new Client)->forceFill(['redirect_uris' => $redirectUris]));
}

it('lets a canonical loopback redirect float its port', function (string $registered, string $candidate): void {
    expect(loopbackClient([$registered])->allowsRedirectUri($candidate))->toBeTrue()
        ->and(WebRedirectUri::isCanonicalLoopback($candidate))->toBeTrue();
})->with([
    'IPv4' => ['http://127.0.0.1:8400/callback', 'http://127.0.0.1:59123/callback'],
    'IPv4, no port registered' => ['http://127.0.0.1/callback', 'http://127.0.0.1:59123/callback'],
    'IPv4, no port asked' => ['http://127.0.0.1:8400/callback', 'http://127.0.0.1/callback'],
    'IPv6' => ['http://[::1]:8400/callback', 'http://[::1]:59123/callback'],
    'localhost' => ['http://localhost/callback', 'http://localhost:5555/callback'],
    'with a query' => ['http://127.0.0.1/callback?app=cli', 'http://127.0.0.1:59123/callback?app=cli'],
]);

it('does not float the port for a loopback redirect that is not in canonical form', function (string $candidate): void {
    $client = loopbackClient([
        'http://127.0.0.1:8400/callback',
        'http://[::1]:8400/callback',
        'http://localhost/callback',
    ]);

    expect($client->allowsRedirectUri($candidate))->toBeFalse()
        ->and(WebRedirectUri::isCanonicalLoopback($candidate))->toBeFalse()
        ->and(WebRedirectUri::loopbackWithoutPort($candidate))->toBeNull();
})->with([
    'backslash before userinfo' => ['http://attacker.invalid\\@127.0.0.1:59123/callback'],
    'backslash before userinfo, IPv6' => ['http://attacker.invalid\\@[::1]:59123/callback'],
    'backslash before userinfo, localhost' => ['http://attacker.invalid\\@localhost:5555/callback'],
    'userinfo' => ['http://attacker.invalid@127.0.0.1:59123/callback'],
    'user and password' => ['http://user:pass@127.0.0.1:59123/callback'],
    'empty userinfo' => ['http://@127.0.0.1:59123/callback'],
    'loopback as userinfo' => ['http://127.0.0.1:1@attacker.invalid/callback'],
    'backslash in path' => ['http://127.0.0.1:59123\\callback'],
    'fragment' => ['http://127.0.0.1:59123/callback#x'],
    'empty fragment' => ['http://127.0.0.1:59123/callback#'],
    'empty port' => ['http://127.0.0.1:/callback'],
    'leading-zero port' => ['http://127.0.0.1:08400/callback'],
    'upper-case scheme' => ['HTTP://127.0.0.1:59123/callback'],
    'upper-case host' => ['http://LOCALHOST:5555/callback'],
    'https' => ['https://127.0.0.1:59123/callback'],
    'tab' => ["http://127.0.0.1:59123/callback\t"],
    'space' => ['http://127.0.0.1:59123/call back'],
    'newline' => ["http://127.0.0.1:59123/callback\n"],
    'NUL' => ["http://127.0.0.1:59123/callback\0"],
    'DEL' => ["http://127.0.0.1:59123/callback\x7f"],
    'bare IPv6' => ['http://::1:59123/callback'],
])->group('security');

it('still accepts a non-canonical redirect that is registered exactly', function (): void {
    $odd = 'http://127.0.0.1:8400/callback#registered';

    expect(loopbackClient([$odd])->allowsRedirectUri($odd))->toBeTrue()
        // …but never as the base for a floated port.
        ->and(loopbackClient([$odd])->allowsRedirectUri('http://127.0.0.1:59123/callback'))->toBeFalse();
});

it('does not float the port for a non-loopback host', function (): void {
    expect(loopbackClient(['http://127.0.0.1:8400/callback'])->allowsRedirectUri('http://127.0.0.2:8400/callback'))->toBeFalse()
        ->and(loopbackClient(['https://app.example.test/callback'])->allowsRedirectUri('https://app.example.test:8443/callback'))->toBeFalse();
});
