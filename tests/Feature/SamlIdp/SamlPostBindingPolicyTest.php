<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\ValueObjects\SamlResponse;

/**
 * The POST binding has to survive the host's own content policy.
 *
 * A self-submitting form aimed at a service provider's ACS is, to a browser, exactly
 * what `form-action` exists to refuse, and its auto-submit is exactly what a `script-src`
 * without `'unsafe-inline'` exists to refuse. So a host that hardens its headers — which
 * every host should — silently breaks its own federation: the user watches a blank page
 * and the SP is never told anything happened. There is no PHP-level symptom, which is
 * why this shipped.
 *
 * The remedy that suggests itself is loosening the global policy, trading every page's
 * form-hijack and injected-script protection for one endpoint. These assertions exist to
 * make the narrow answer the durable one.
 */
it('emits a policy that permits this ACS and nothing else', function (): void {
    $binding = (new SamlResponse(
        xml: '<Response/>',
        encoded: base64_encode('<Response/>'),
        acsUrl: 'https://sp.example.test:8443/acs/consume?tenant=acme',
        relayState: 'state',
    ))->toPostBinding();

    // The origin, not the path: `form-action` matches on a path prefix, and a service
    // provider is free to append a query string to its own endpoint.
    expect($binding->contentSecurityPolicy)
        ->toContain('form-action https://sp.example.test:8443')
        ->not->toContain('/acs/consume')
        ->not->toContain("form-action 'self'")
        // Nothing else may load at all. The page is one form and one line of script.
        ->toContain("default-src 'none'")
        ->toContain("base-uri 'none'");
});

it('permits its own submit script by nonce rather than by unsafe-inline', function (): void {
    $binding = (new SamlResponse(
        xml: '<Response/>',
        encoded: base64_encode('<Response/>'),
        acsUrl: 'https://sp.example.test/acs',
    ))->toPostBinding();

    expect($binding->contentSecurityPolicy)->not->toContain('unsafe-inline');

    // An event-handler attribute cannot be nonced — `onload` is permitted only by
    // 'unsafe-inline', which is all-or-nothing for the whole document. So the submit
    // has to be a script tag, and the nonce in the policy has to be the one on the tag.
    expect($binding->html)->not->toContain('onload');

    preg_match('/nonce-([A-Za-z0-9+\/=]+)/', $binding->contentSecurityPolicy, $policy);
    preg_match('/<script nonce="([^"]+)"/', $binding->html, $markup);

    expect($policy[1] ?? 'policy')->toBe($markup[1] ?? 'markup');
});

it('never repeats a nonce across responses', function (): void {
    $response = new SamlResponse(
        xml: '<Response/>',
        encoded: base64_encode('<Response/>'),
        acsUrl: 'https://sp.example.test/acs',
    );

    // A nonce reused across responses is one an attacker can pre-load a script against.
    expect($response->toPostBinding()->contentSecurityPolicy)
        ->not->toBe($response->toPostBinding()->contentSecurityPolicy);
});

it('carries the policy on the response a controller returns', function (): void {
    $http = (new SamlResponse(
        xml: '<Response/>',
        encoded: base64_encode('<Response/>'),
        acsUrl: 'https://sp.example.test/acs',
    ))->toPostBinding()->toResponse();

    expect($http->headers->get('Content-Security-Policy'))
        ->toContain('form-action https://sp.example.test')
        // The page holds a signed assertion for the fraction of a second it exists.
        ->and($http->headers->get('Cache-Control'))->toContain('no-store');
});

/**
 * A malformed ACS must not be able to write its own directives.
 *
 * The origin goes into a response header, so an unparseable value echoed verbatim is
 * header injection with extra steps: a semicolon in the URL introduces directives of the
 * attacker's choosing, and because the first occurrence of a directive wins, they land
 * BEFORE the `base-uri` and `frame-ancestors` this page relies on. It takes an
 * admin-registered service provider to reach, which is why it is a fail-closed question
 * rather than an open door — but "only an admin can do it" is not a security property.
 */
it('refuses to name an unparseable ACS as a policy source', function (): void {
    $binding = (new SamlResponse(
        xml: '<Response/>',
        encoded: base64_encode('<Response/>'),
        acsUrl: 'not a url; frame-ancestors *; base-uri *',
    ))->toPostBinding();

    expect($binding->contentSecurityPolicy)
        ->toContain("form-action 'none'")
        ->not->toContain('frame-ancestors *')
        ->not->toContain('base-uri *');
});
