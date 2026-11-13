<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Support\AuthnRequestParser;
use Cbox\Id\SamlIdp\Support\RedirectBindingInflater;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * A redirect-binding SAML message is raw DEFLATE, and DEFLATE compresses a run of one byte
 * about a thousandfold: a SAMLRequest of tens of kilobytes, sent before anyone signs in,
 * would otherwise inflate to tens of megabytes per request. Past the cap it is refused.
 */

/** Raw DEFLATE of $bytes of one letter, built a mebibyte at a time so the test never holds it. */
function samlBomb(int $bytes): string
{
    $context = deflate_init(ZLIB_ENCODING_RAW, ['level' => 9]);
    $chunk = str_repeat('A', 1024 * 1024);
    $out = '';

    for ($written = 0; $written < $bytes; $written += strlen($chunk)) {
        $out .= deflate_add($context, $chunk, ZLIB_NO_FLUSH);
    }

    return base64_encode($out.deflate_add($context, '', ZLIB_FINISH));
}

function inflationPeak(Closure $run): int
{
    gc_collect_cycles();
    memory_reset_peak_usage();
    $before = memory_get_usage();
    $run();

    return memory_get_peak_usage() - $before;
}

it('refuses an AuthnRequest that inflates past the cap, without allocating it', function (): void {
    $bomb = samlBomb(64 * 1024 * 1024);

    $peak = inflationPeak(function () use ($bomb): void {
        expect(fn () => app(AuthnRequestParser::class)->parse($bomb, true))
            ->toThrow(InvalidAuthnRequest::class, 'could not be inflated');
    });

    expect(strlen($bomb))->toBeLessThan(200_000)
        ->and($peak)->toBeLessThan(16 * 1024 * 1024);
});

it('still parses an ordinary redirect-binding AuthnRequest', function (): void {
    $xml = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        .' ID="_abc123" Version="2.0" IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'" AssertionConsumerServiceURL="https://sp.example/acs">'
        .'<saml:Issuer>https://sp.example/metadata</saml:Issuer></samlp:AuthnRequest>';

    $parsed = app(AuthnRequestParser::class)->parse(base64_encode((string) gzdeflate($xml)), true);

    expect($parsed->id)->toBe('_abc123')
        ->and($parsed->issuer)->toBe('https://sp.example/metadata');
});

it('refuses a LogoutRequest that inflates past the cap, without allocating it', function (): void {
    $bomb = samlBomb(64 * 1024 * 1024);

    $peak = inflationPeak(function () use ($bomb): void {
        $this->get('/sso/saml/idp/slo?'.http_build_query(['SAMLRequest' => $bomb]))->assertStatus(400);
    });

    expect($peak)->toBeLessThan(16 * 1024 * 1024);
});

it('caps the inflater at one mebibyte', function (): void {
    expect(strlen((string) RedirectBindingInflater::inflate((string) gzdeflate(str_repeat('A', 1000 * 1000)))))->toBe(1000 * 1000)
        ->and(RedirectBindingInflater::inflate((string) gzdeflate(str_repeat('A', RedirectBindingInflater::MAX_BYTES + 1))))->toBeNull()
        ->and(RedirectBindingInflater::inflate('not deflate'))->toBeNull();
});
