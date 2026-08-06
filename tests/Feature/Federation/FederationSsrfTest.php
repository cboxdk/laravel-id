<?php

declare(strict_types=1);

use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\OidcDiscovery;
use Cbox\Id\Federation\Saml\SamlMetadataImporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

/**
 * Every outbound federation fetch, refused when its host resolves somewhere private.
 *
 * `SafeFederationUrl::pinnedOptions()` is the only SSRF protection on these paths, and
 * three of its four call sites had no test at all. That absence is not theoretical: an
 * SSRF pin on the outbound SCIM client was replaced with an empty array during this
 * review's own falsification work, swept into a commit, and RELEASED — and every suite
 * stayed green, because nothing asserted on it. A guard nothing asserts on is a guard
 * that can leave without a sound.
 *
 * The guard is enabled per test (the flow tests disable it file-wide to reach fixtures),
 * and Http::fake is armed for the blocked address so a bypass would visibly SUCCEED
 * rather than merely erroring on an unreachable network — otherwise this would pass for
 * the wrong reason on a machine with no route out.
 */
beforeEach(function (): void {
    config(['cbox-id.federation.verify_url' => true]);
    Http::fake(['*' => Http::response(['should' => 'never be requested'], 200)]);
});

it('refuses to fetch a discovery document from an internal address', function (): void {
    // The guard's own exception, not a wrapped OidcDiscoveryFailed. All three paths
    // agree on this, which is worth pinning: "unsafe URL" answers the question that
    // "discovery failed" only raises, and a caller distinguishing a refusal from an
    // unreachable IdP needs the difference.
    expect(fn () => app(OidcDiscovery::class)->fromIssuer('http://169.254.169.254'))
        ->toThrow(UnsafeFederationUrl::class);

    Http::assertNothingSent();
});

/**
 * The metadata URL is administrator input; the JWKS URI one layer in is not — it comes
 * from the remote IdP's own discovery document, so a federated IdP can point it wherever
 * it likes. Both go through the same guard, which is the reason that matters.
 */
it('refuses to import SAML metadata from the cloud metadata service', function (): void {
    // The importer lets the guard's own exception through, which is clearer than
    // wrapping it: "unsafe URL" answers the question, "import failed" only raises it.
    expect(fn () => app(SamlMetadataImporter::class)->fromUrl('http://169.254.169.254/metadata'))
        ->toThrow(UnsafeFederationUrl::class);

    Http::assertNothingSent();
});

it('refuses to import SAML metadata from a private range', function (): void {
    expect(fn () => app(SamlMetadataImporter::class)->fromUrl('http://10.0.0.1/metadata'))
        ->toThrow(UnsafeFederationUrl::class);

    Http::assertNothingSent();
});
