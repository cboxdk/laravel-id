<?php

declare(strict_types=1);

use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Support\BrowserStartUrl;

/*
 * A federation start URL is the one tenant-configured value this platform puts in a
 * `Location:` header. The destination is somebody else's IdP by design, so the host
 * cannot be constrained — but the SHAPE can, and every shape refused below turns an
 * ordinary SSO connection into an open-redirect primitive flying this platform's domain:
 * a link to `/sso/saml/{connection}/login` that looks like the customer's own sign-in
 * and lands somewhere else.
 */
it('accepts an ordinary IdP start URL, query string and all', function (string $url): void {
    expect(BrowserStartUrl::assert($url, 'idp_sso_url'))->toBe($url);
})->with([
    'https://acme.okta.com/app/acme_cboxid/exk1/sso/saml',
    'https://login.microsoftonline.com/tenant-id/saml2',
    'https://id.example.test/authorize?prompt=login',
]);

it('refuses a start URL that is not https', function (): void {
    // Plaintext puts the SAMLRequest, the RelayState and the redirect back through a
    // network attacker in the clear — and hands them a page the person believes is their
    // employer's sign-in.
    expect(fn () => BrowserStartUrl::assert('http://id.example.test/authorize', 'authorization_endpoint'))
        ->toThrow(UnsafeFederationUrl::class, 'must be an https URL');
})->group('security');

it('refuses a scheme that is not a URL a browser navigates to', function (string $url): void {
    expect(fn () => BrowserStartUrl::assert($url, 'idp_sso_url'))->toThrow(UnsafeFederationUrl::class);
})->with([
    'javascript:alert(document.domain)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    // Not absolute: no host at all, so it would resolve against this platform's own
    // origin and redirect inside the console.
    '/console/settings',
])->group('security');

it('refuses embedded credentials, which make one host read as another', function (): void {
    // Reads as Okta to a person scanning the URL bar; resolves to evil.example.
    expect(fn () => BrowserStartUrl::assert('https://acme.okta.com@evil.example/sso', 'idp_sso_url'))
        ->toThrow(UnsafeFederationUrl::class, 'must not carry credentials');
})->group('security');

it('refuses a fragment, which never reaches the server it is aimed at', function (): void {
    expect(fn () => BrowserStartUrl::assert('https://id.example.test/sso#smuggled', 'idp_sso_url'))
        ->toThrow(UnsafeFederationUrl::class, 'must not carry a fragment');
})->group('security');
