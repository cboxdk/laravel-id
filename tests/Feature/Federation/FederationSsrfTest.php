<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\AssertionValidator;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Exceptions\UnsafeFederationUrl;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\OidcDiscovery;
use Cbox\Id\Federation\Saml\SamlMetadataImporter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

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

/**
 * The JWKS fetch — the one this file's own docblock argues matters most, and which had
 * no test at all.
 *
 * Discovery and SAML metadata are fetched from a URL an ADMINISTRATOR typed. `jwks_uri`
 * is not: it is read out of the remote IdP's discovery document, so whoever controls that
 * document chooses the address this server connects to. It is fetched on the VALIDATION
 * path — during a live sign-in, again on a key rotation — rather than once at setup.
 *
 * The prose above already said all of that. Nothing asserted it, which is the difference
 * between a reason and a control: the pin on the outbound SCIM client was replaced with an
 * empty array during this review's own falsification work and shipped green, because
 * nothing asserted on it either.
 *
 * A REAL CONNECTION, not a hand-built config. My first version of this test passed an
 * `OidcConnectionConfig` to `validate()`, which takes a `Connection` — so it threw a
 * TypeError that the test's own `catch (Throwable)` swallowed, and the assertion below
 * held because NOTHING had run. Deleting the pin left it green. The mutation is what
 * caught that, and it is why the mutation is worth running on a test that looks obvious.
 */
/**
 * An active OIDC connection whose IdP advertises `$jwksUri`.
 *
 * Defined here rather than borrowed from `OidcValidationTest`: Pest's global helpers only
 * exist once the file declaring them has loaded, so a borrowed one makes running THIS
 * file alone a fatal error — and running one file alone is exactly what somebody does
 * when investigating a security control.
 */
function ssrfConnection(string $jwksUri): Connection
{
    $connections = app(Connections::class);

    $connection = $connections->create(
        (string) Str::ulid(),
        ConnectionType::Oidc,
        'Hostile IdP',
        ['issuer' => 'https://idp.test', 'client_id' => 'client-123', 'jwks_uri' => $jwksUri],
    );
    $connections->activate($connection->organization_id, $connection->id);

    return $connection->refresh();
}

it('never fetches a JWKS from an internal address, whatever the IdP advertises', function (): void {
    $connection = ssrfConnection(
        // What a hostile — or merely compromised — IdP puts in its own discovery document.
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
    );

    // The assertion cannot verify: there is no key, which is the safe outcome and not the
    // property under test.
    // `keys()` is evaluated as the ARGUMENT to JWT::decode, so the JWKS fetch is attempted
    // before any parsing — the token's shape is irrelevant to what this asserts.
    expect(fn () => app(AssertionValidator::class)->validate($connection, 'not.a.jwt'))
        ->toThrow(InvalidAssertion::class);

    // THE PROPERTY. "We did not connect to the metadata service" — that the signature then
    // failed is a consequence of refusing, not the thing being asserted.
    Http::assertNothingSent();
});

it('never fetches a JWKS from a private range', function (): void {
    $connection = ssrfConnection('http://10.0.0.1/.well-known/jwks.json');

    expect(fn () => app(AssertionValidator::class)->validate($connection, 'not.a.jwt'))
        ->toThrow(InvalidAssertion::class);

    Http::assertNothingSent();
});
