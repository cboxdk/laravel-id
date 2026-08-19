<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\Contracts\IssuerResolver;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\MessageGuard;
use Cbox\Id\SamlIdp\Support\RedirectBindingSignature;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OneLogin\Saml2\Utils as SamlUtils;
use RobRichards\XMLSecLibs\XMLSecurityKey;

uses(RefreshDatabase::class);

const IDP_SSO_ENDPOINT = '/sso/saml/idp/sso';

const IDP_SLO_ROUTE = '/sso/saml/idp/slo';

/** The `SAMLResponse` carried by a self-submitting POST form, decoded. */
function postedSamlResponse(string $html): string
{
    expect($html)->toContain('name="SAMLResponse"');

    preg_match('/name="SAMLResponse" value="([^"]+)"/', $html, $matches);

    return (string) base64_decode(htmlspecialchars_decode($matches[1] ?? '', ENT_QUOTES), true);
}

/**
 * A `<samlp:LogoutRequest>` carrying an enveloped XML-DSig — the HTTP-POST
 * binding's authentication (there is no detached query signature).
 */
function signedPostLogoutRequest(string $entityId, string $privateKey, string $certificate, ?string $id = null): string
{
    $xml = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        .' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        .' ID="'.($id ?? '_'.bin2hex(random_bytes(16))).'" Version="2.0"'
        .' IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'"'
        .' Destination="'.IdpDescriptor::sloUrl().'">'
        .'<saml:Issuer>'.$entityId.'</saml:Issuer>'
        .'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test</saml:NameID>'
        .'</samlp:LogoutRequest>';

    return base64_encode(SamlUtils::addSign($xml, $privateKey, SamlUtils::formatCert($certificate)));
}

/*
|--------------------------------------------------------------------------
| A — metadata must describe what the IdP actually does
|--------------------------------------------------------------------------
|
| An SP treats metadata as authoritative. An attribute that over-promises is
| not cosmetic: it is an outage on the SP's side that no log here explains.
*/

it('declares WantAuthnRequestsSigned only while every registered SP requires signing', function (): void {
    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="false"');

    $this->registerSamlServiceProvider(
        entityId: 'https://strict.example.test/metadata',
        certificate: $this->samlSigningKeypair()['certificate'],
        wantAuthnRequestsSigned: true,
    );

    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="true"');
});

it('does not claim IdP-wide signing enforcement one SP does not get', function (): void {
    // Metadata carries ONE WantAuthnRequestsSigned for the whole IDPSSODescriptor.
    // Publishing "true" because a single SP requires signing tells every OTHER SP
    // the IdP refuses unsigned requests — while it happily processes theirs.
    $this->registerSamlServiceProvider(
        entityId: 'https://strict.example.test/metadata',
        acsUrl: 'https://strict.example.test/acs',
        certificate: $this->samlSigningKeypair()['certificate'],
        wantAuthnRequestsSigned: true,
    );
    $relaxed = $this->registerSamlServiceProvider(
        entityId: 'https://relaxed.example.test/metadata',
        acsUrl: 'https://relaxed.example.test/acs',
    );

    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="false"');

    // And the claim is true: the relaxed SP's unsigned request is still answered.
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($relaxed->entity_id));

    expect($request->spEntityId)->toBe($relaxed->entity_id);
});

/**
 * Metadata is cached — an unauthenticated endpoint that SPs poll should not read and
 * rebuild on every request — and this is the case that cache has to get right.
 *
 * Disabling an SP changes neither the row count nor, necessarily, anything a coarse
 * "has the table changed" stamp would notice within the same second. It changes the
 * answer: the strict SP stops counting toward IdP-wide signing enforcement, and every
 * remaining SP is told the truth about what this IdP demands. A stale document here
 * tells the relaxed SPs their unsigned requests will be refused, which is an outage
 * on their side and nothing in our logs.
 */
it('republishes metadata the moment a registration is disabled', function (): void {
    $strict = $this->registerSamlServiceProvider(
        entityId: 'https://strict.example.test/metadata',
        certificate: $this->samlSigningKeypair()['certificate'],
        wantAuthnRequestsSigned: true,
    );

    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="true"');

    // Read twice: the second call is the one served from cache, and it must still be
    // the document the first call built.
    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="true"');

    $strict->forceFill(['status' => ServiceProviderStatus::Disabled])->save();

    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="false"');
});

it('lets an operator pin WantAuthnRequestsSigned regardless of the registrations', function (): void {
    config()->set('cbox-id.saml_idp.want_authn_requests_signed', true);

    expect($this->samlIdp()->metadata())->toContain('WantAuthnRequestsSigned="true"');
});

/*
| The NameID format URNs are asserted as LITERAL strings, never through the enum.
| A test written against `NameIdFormat::Unspecified->value` asserts that the code
| agrees with itself and passes just as happily when the constant is a URN no
| specification defines — which is exactly how a fabricated
| `urn:…:SAML:2.0:nameid-format:unspecified` survived here.
*/

it('spells unspecified with the URN SAML actually defines', function (): void {
    // SAML core 2.0 §8.3.1 reuses the SAML 1.1 identifier — there is no 2.0
    // spelling of `unspecified`, and an SP sending the real one must be answered.
    expect(NameIdFormat::Unspecified->value)->toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
        ->and(NameIdFormat::EmailAddress->value)->toBe('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
        ->and(NameIdFormat::Persistent->value)->toBe('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
        ->and(NameIdFormat::Transient->value)->toBe('urn:oasis:names:tc:SAML:2.0:nameid-format:transient');
});

it('advertises only the NameID formats it actually emits', function (): void {
    $this->registerSamlServiceProvider(nameIdFormat: NameIdFormat::Persistent);

    $metadata = $this->samlIdp()->metadata();

    expect($metadata)
        ->toContain('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent')
        // `unspecified` is honoured (it means "IdP, you choose"), so it is honest
        // to advertise it. `transient` is emitted by no registered SP.
        ->toContain('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
        ->not->toContain('urn:oasis:names:tc:SAML:2.0:nameid-format:transient')
        // And never the URN that does not exist.
        ->not->toContain('urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified');
});

it('advertises no format a sibling SP would be refused for requesting', function (): void {
    // One IDPSSODescriptor serves every SP. Salesforce fills its NameID picklist
    // from the imported metadata and Shibboleth's nameIDFormatPrecedence defaults
    // to the first entry — so a union of the registered SPs' formats hands a third
    // SP a menu it gets InvalidNameIDPolicy for ordering from.
    $this->registerSamlServiceProvider(
        entityId: 'https://salesforce.example.test/metadata',
        acsUrl: 'https://salesforce.example.test/acs',
        nameIdFormat: NameIdFormat::EmailAddress,
    );
    $this->registerSamlServiceProvider(
        entityId: 'https://workday.example.test/metadata',
        acsUrl: 'https://workday.example.test/acs',
        nameIdFormat: NameIdFormat::Persistent,
    );

    expect($this->samlIdp()->metadata())
        ->toContain('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
        ->not->toContain('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress')
        ->not->toContain('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
});

it('answers every advertised NameID format, for every registered SP', function (): void {
    // The invariant that keeps the two lists from drifting again: whatever metadata
    // offers, every registered SP can actually be asked for it.
    $sps = [
        $this->registerSamlServiceProvider(
            entityId: 'https://salesforce.example.test/metadata',
            acsUrl: 'https://salesforce.example.test/acs',
            nameIdFormat: NameIdFormat::EmailAddress,
        ),
        $this->registerSamlServiceProvider(
            entityId: 'https://workday.example.test/metadata',
            acsUrl: 'https://workday.example.test/acs',
            nameIdFormat: NameIdFormat::Persistent,
        ),
    ];

    preg_match_all('/<md:NameIDFormat>([^<]+)<\/md:NameIDFormat>/', $this->samlIdp()->metadata(), $matches);

    expect($matches[1])->not->toBeEmpty();

    $id = 0;
    foreach ($matches[1] as $format) {
        foreach ($sps as $sp) {
            $request = $this->makeRedirectAuthnRequest(
                $sp->entity_id,
                id: '_advertised'.($id++),
                nameIdFormat: $format,
            );

            expect($this->samlIdp()->parseAuthnRequest($request)->spEntityId)->toBe($sp->entity_id);
        }
    }
});

it('advertises both SLO bindings because both are now verified', function (): void {
    $metadata = $this->samlIdp()->metadata();

    preg_match_all('/<md:SingleLogoutService Binding="([^"]+)"/', $metadata, $matches);

    expect($matches[1])->toBe([
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ]);
});

/*
|--------------------------------------------------------------------------
| A/D — key rollover has an overlap window
|--------------------------------------------------------------------------
*/

it('keeps publishing the outgoing certificate while a key rotates out', function (): void {
    // Publishing once materialises the certificate for the current key.
    expect(substr_count($this->samlIdp()->metadata(), '<ds:X509Certificate>'))->toBe(1);

    $outgoing = app(IdpKeyMaterial::class)->active()->certificatePem;
    app(KeyManager::class)->rotate();

    $metadata = $this->samlIdp()->metadata();
    $incoming = app(IdpKeyMaterial::class)->active()->certificatePem;

    // Both, active first: an SP that imported either side of the switch verifies.
    expect(substr_count($metadata, '<ds:X509Certificate>'))->toBe(2)
        ->and($incoming)->not->toBe($outgoing);

    $body = static fn (string $pem): string => (string) preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem);

    expect($metadata)->toContain($body($incoming))->toContain($body($outgoing));
});

/*
|--------------------------------------------------------------------------
| C — the redirect binding signs the octets AS TRANSMITTED
|--------------------------------------------------------------------------
*/

it('verifies a redirect-binding signature over the octets as transmitted', function (): void {
    $keypair = $this->samlSigningKeypair();
    $samlRequest = $this->makeRedirectAuthnRequest('https://sp.example.test/metadata');
    $sigAlg = XMLSecurityKey::RSA_SHA256;

    // A RelayState with a space AND a tilde — the two characters where PHP's
    // urlencode ("+", "%7E") and RFC 3986 ("%20", literal "~") disagree. Entra
    // and Ping send the latter; every deep link with a space used to 400 here.
    $relayState = 'https://app.example.test/reports?q=last quarter~summary';

    $signedQuery = 'SAMLRequest='.rawurlencode($samlRequest)
        .'&RelayState='.rawurlencode($relayState)
        .'&SigAlg='.rawurlencode($sigAlg);

    expect($signedQuery)->toContain('%20')->toContain('~');

    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
    $key->loadKey($keypair['privateKey'], false);
    $signature = base64_encode((string) $key->signData($signedQuery));

    $rawQuery = $signedQuery.'&Signature='.rawurlencode($signature);
    $verifier = new RedirectBindingSignature;

    // As transmitted: verifies.
    $verifier->verify($samlRequest, $relayState, $signature, $sigAlg, $keypair['certificate'], $rawQuery);

    // And the re-encoding path — all we can do without the transmitted octets —
    // is exactly where this used to fail, which is why the raw query is used.
    expect(fn () => $verifier->verify($samlRequest, $relayState, $signature, $sigAlg, $keypair['certificate'], ''))
        ->toThrow(InvalidAuthnRequest::class);
});

it('ignores a query string that does not match the parameters being verified', function (): void {
    $keypair = $this->samlSigningKeypair();
    $samlRequest = $this->makeRedirectAuthnRequest('https://sp.example.test/metadata');
    $sigAlg = XMLSecurityKey::RSA_SHA256;

    // Signed the ordinary (urlencode) way, as our own test SPs do.
    $signedQuery = 'SAMLRequest='.urlencode($samlRequest).'&SigAlg='.urlencode($sigAlg);
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
    $key->loadKey($keypair['privateKey'], false);
    $signature = base64_encode((string) $key->signData($signedQuery));

    // A query string from some OTHER request must never be used to verify these
    // parameters — it falls back to the reconstruction, which still verifies.
    (new RedirectBindingSignature)->verify(
        $samlRequest,
        null,
        $signature,
        $sigAlg,
        $keypair['certificate'],
        'SAMLRequest=something-else&SigAlg='.urlencode($sigAlg).'&Signature=zzz',
    );
})->throwsNoExceptions();

it('carries the transmitted octets across the login hand-off and back', function (): void {
    config()->set('cbox-id.saml_idp.login_url', 'https://app.test/login');

    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(
        certificate: $keypair['certificate'],
        wantAuthnRequestsSigned: true,
    );

    // A RelayState with a space, encoded the way SimpleSAMLphp — and every other
    // PHP-based SP — encodes it: "+", not "%20". This is the whole test: the
    // signature covers those octets, and any re-encoding of the query on the way to
    // the host's login and back produces a different, unverifiable byte string.
    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);
    $relayState = 'https://app.example.test/reports?q=last quarter';
    $sigAlg = XMLSecurityKey::RSA_SHA256;

    $signedQuery = 'SAMLRequest='.urlencode($samlRequest)
        .'&RelayState='.urlencode($relayState)
        .'&SigAlg='.urlencode($sigAlg);

    expect($signedQuery)->toContain('quarter')->toContain('+');

    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
    $key->loadKey($keypair['privateKey'], false);
    $signature = base64_encode((string) $key->signData($signedQuery));

    $rawQuery = $signedQuery.'&Signature='.urlencode($signature);

    // Leg 1 — the SP's redirect arrives, verifies, and is handed off to the login.
    $handoff = $this->get(IDP_SSO_ENDPOINT.'?'.$rawQuery);
    $handoff->assertRedirect();

    parse_str((string) parse_url((string) $handoff->headers->get('Location'), PHP_URL_QUERY), $params);
    $returnTo = $params['return_to'] ?? '';
    expect($returnTo)->toBeString();

    // The octets survived: not `%20`, not re-ordered by ksort.
    expect((string) $returnTo)->toContain('&Signature=')
        ->and((string) parse_url((string) $returnTo, PHP_URL_QUERY))->toBe($rawQuery);

    // Leg 2 — the host returns the browser to exactly that URL once the user has
    // signed in. The same signature must verify a second time; it used to fail
    // here, AFTER the login, for every SP that percent-encodes differently.
    $subject = $this->makeUser('alice@sp.example.test');

    $resumed = $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get((string) $returnTo);

    $resumed->assertOk();

    expect(postedSamlResponse((string) $resumed->getContent()))->toContain('<saml:Assertion');
});

/*
|--------------------------------------------------------------------------
| F — Destination, freshness and single use
|--------------------------------------------------------------------------
*/

it('refuses an AuthnRequest addressed to a different endpoint', function (): void {
    $sp = $this->registerSamlServiceProvider();

    $request = $this->makeRedirectAuthnRequest($sp->entity_id, destination: 'https://other-idp.test/sso');

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request))
        ->toThrow(InvalidAuthnRequest::class, 'Destination');
});

it('refuses a signed AuthnRequest that carries no Destination at all', function (): void {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    // SAML core §3.2.1: Destination is a MUST on a signed message.
    $samlRequest = $this->makeSignedPostAuthnRequest(
        $sp->entity_id,
        $keypair['privateKey'],
        $keypair['certificate'],
        destination: '',
    );

    expect(fn () => $this->samlIdp()->parseAuthnRequest($samlRequest, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class, 'Destination');
});

it('accepts a Destination naming the endpoint the request actually arrived at', function (): void {
    // The tenant federates on its platform subdomain and its SPs import that.
    config()->set('cbox-id.saml_idp.entity_id', null);
    config()->set('cbox-id.issuer', 'https://acme.cboxid.test');

    $sp = $this->registerSamlServiceProvider();
    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id, destination: IdpDescriptor::ssoUrl());

    // Later it verifies a custom domain: the published endpoints legitimately move,
    // while the old host stays live and every SP that has not re-imported metadata
    // keeps addressing it. SAML bindings §3.4.5.2 compares Destination against where
    // the message WAS RECEIVED — comparing it against the new published URL instead
    // would refuse every one of those SPs at once.
    config()->set('cbox-id.issuer', 'https://login.acme.test');
    app()->forgetInstance(IssuerResolver::class);

    $response = $this->get('https://acme.cboxid.test'.IDP_SSO_ENDPOINT.'?'.http_build_query([
        'SAMLRequest' => $samlRequest,
    ]));

    // 401 = "authenticate first", i.e. it cleared validation. A Destination refusal
    // is a 200 carrying a signed SAML error Response.
    $response->assertStatus(401);
});

it('still refuses a Destination naming neither the received nor the published endpoint', function (): void {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id, destination: 'https://evil.example/sso');

    // Accepting the receiving location must not become "accept anything": the
    // request never arrived at evil.example, so it is refused there too.
    $html = (string) $this->get('https://acme.cboxid.test'.IDP_SSO_ENDPOINT.'?'.http_build_query([
        'SAMLRequest' => $samlRequest,
    ]))->getContent();

    expect(postedSamlResponse($html))->toContain('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
});

it('reports a refusal with a top-level StatusCode from the top-level list', function (): void {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id, destination: 'https://other-idp.test/sso');

    $html = (string) $this->get(IDP_SSO_ENDPOINT.'?'.http_build_query(['SAMLRequest' => $samlRequest]))
        ->assertOk()
        ->getContent();

    $xml = postedSamlResponse($html);

    // SAML core §3.2.2.2: the topmost StatusCode MUST come from the top-level list
    // (Success, Requester, Responder, VersionMismatch). RequestDenied is a
    // SECOND-level code, and Shibboleth and Sustainsys.Saml2 both branch on the
    // top-level one — a second-level code there reads as an unknown failure.
    preg_match('/<samlp:StatusCode Value="([^"]+)"/', $xml, $topLevel);

    expect($topLevel[1] ?? '')->toBe('urn:oasis:names:tc:SAML:2.0:status:Requester')
        ->and($xml)->toContain('urn:oasis:names:tc:SAML:2.0:status:RequestDenied');
});

it('refuses a stale AuthnRequest', function (): void {
    $sp = $this->registerSamlServiceProvider();

    $request = $this->makeRedirectAuthnRequest($sp->entity_id, issueInstant: gmdate('Y-m-d\TH:i:s\Z', time() - 7200));

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request))
        ->toThrow(InvalidAuthnRequest::class, 'stale');
});

it('answers one AuthnRequest exactly once, but tolerates re-parsing it across the login hand-off', function (): void {
    $sp = $this->registerSamlServiceProvider();
    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);

    // Parsed before the hand-off to the host's login, and again when the browser
    // comes back with the same request — that is NOT a replay.
    $this->samlIdp()->parseAuthnRequest($samlRequest);
    $request = $this->samlIdp()->parseAuthnRequest($samlRequest);

    $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'a@sp.example.test']);

    // A SECOND assertion for the same request id is.
    expect(fn () => $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'a@sp.example.test']))
        ->toThrow(InvalidAuthnRequest::class, 'replay');
});

/*
|--------------------------------------------------------------------------
| A/G — an unsatisfiable NameIDPolicy is answered in SAML, not with a 400
|--------------------------------------------------------------------------
*/

it('refuses a NameIDPolicy the registered SP cannot be answered under', function (): void {
    $sp = $this->registerSamlServiceProvider(nameIdFormat: NameIdFormat::EmailAddress);

    $request = $this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: NameIdFormat::Persistent->value);

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request))
        ->toThrow(InvalidAuthnRequest::class, 'NameIDPolicy');
});

it('accepts a NameIDPolicy of unspecified as "IdP, you choose"', function (string $urn): void {
    $sp = $this->registerSamlServiceProvider(nameIdFormat: NameIdFormat::EmailAddress);

    // The URNs are literal on purpose: ADFS, WSO2, Shibboleth and every other
    // OpenSAML-based SP send the spec-defined 1.1 spelling (1.0 in SAML 1.x
    // compatibility mode). Neither may be answered with InvalidNameIDPolicy.
    $request = $this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: $urn);
    $response = $this->samlIdp()->issueResponse(
        $this->samlIdp()->parseAuthnRequest($request),
        'user-1',
        ['email' => 'alice@sp.example.test'],
    );

    expect($response->xml)->toContain('Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"');
})->with([
    'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    'urn:oasis:names:tc:SAML:1.0:nameid-format:unspecified',
]);

it('refuses a NameIDPolicy Format that is not a NameID format at all', function (): void {
    $sp = $this->registerSamlServiceProvider(nameIdFormat: NameIdFormat::EmailAddress);

    $request = $this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: 'urn:made:up:format');

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request))
        ->toThrow(InvalidAuthnRequest::class, 'NameIDPolicy');
});

it('POSTs a signed SAML error Response to the ACS instead of an unbranded 400', function (): void {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: NameIdFormat::Persistent->value);

    $response = $this->get(IDP_SSO_ENDPOINT.'?'.http_build_query([
        'SAMLRequest' => $samlRequest,
        'RelayState' => 'back-to-here',
    ]));

    $response->assertOk();
    $html = $response->getContent();
    expect($html)->toBeString();

    $xml = postedSamlResponse((string) $html);

    expect((string) $html)->toContain('action="https://sp.example.test/acs"')
        ->and((string) $html)->toContain('name="RelayState" value="back-to-here"');

    expect($xml)
        ->toContain('urn:oasis:names:tc:SAML:2.0:status:Requester')
        ->toContain('urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy')
        // Signed, so the SP can trust the refusal came from this IdP…
        ->toContain('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
        // …and it carries no assertion.
        ->not->toContain('<saml:Assertion');
});

it('still answers an untrusted refusal with an opaque HTTP status, never a redirect', function (): void {
    // Unknown SP: there is no trusted ACS to deliver a SAML error to, and inventing
    // one would be the open-redirect the ACS pinning exists to prevent.
    $this->get(IDP_SSO_ENDPOINT.'?'.http_build_query([
        'SAMLRequest' => $this->makeRedirectAuthnRequest('https://stranger.test/metadata'),
    ]))->assertStatus(403);
});

/*
|--------------------------------------------------------------------------
| A — HTTP-POST binding Single Logout (what Okta and ADFS prefer)
|--------------------------------------------------------------------------
*/

it('processes a POST-binding LogoutRequest and answers on the POST binding', function (): void {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);
    $sp->forceFill(['slo_url' => 'https://sp.example.test/slo'])->save();

    $response = $this->post(IDP_SLO_ROUTE, [
        'SAMLRequest' => signedPostLogoutRequest($sp->entity_id, $keypair['privateKey'], $keypair['certificate']),
        'RelayState' => 'relay-xyz',
    ]);

    $response->assertOk();
    $html = (string) $response->getContent();

    expect($html)->toContain('action="https://sp.example.test/slo"')
        ->toContain('name="RelayState" value="relay-xyz"');

    $xml = postedSamlResponse($html);

    expect($xml)
        ->toContain('samlp:LogoutResponse')
        ->toContain('urn:oasis:names:tc:SAML:2.0:status:Success')
        // The POST binding has no detached signature, so the response is signed
        // IN the document — an SP with "validate logout response signature" on
        // rejects anything else.
        ->toContain('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256');

    // And a real verifier accepts that signature against our published certificate.
    $document = new DOMDocument;
    $document->loadXML($xml);
    expect(SamlUtils::validateSign(
        $document,
        SamlUtils::formatCert(app(IdpKeyMaterial::class)->active()->certificatePem),
        null,
        'sha256',
    ))->toBeTrue();
});

it('refuses an unsigned POST-binding LogoutRequest', function (): void {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate']);
    $sp->forceFill(['slo_url' => 'https://sp.example.test/slo'])->save();

    $unsigned = '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        .' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_u" Version="2.0"'
        .' IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'">'
        .'<saml:Issuer>'.$sp->entity_id.'</saml:Issuer>'
        .'<saml:NameID>alice@example.test</saml:NameID></samlp:LogoutRequest>';

    $this->post(IDP_SLO_ROUTE, ['SAMLRequest' => base64_encode($unsigned)])->assertStatus(400);
});

it('refuses a POST-binding LogoutRequest signed by a key the SP never registered', function (): void {
    $registered = $this->samlSigningKeypair();
    $attacker = $this->samlSigningKeypair();

    $sp = $this->registerSamlServiceProvider(certificate: $registered['certificate']);
    $sp->forceFill(['slo_url' => 'https://sp.example.test/slo'])->save();

    $this->post(IDP_SLO_ROUTE, [
        'SAMLRequest' => signedPostLogoutRequest($sp->entity_id, $attacker['privateKey'], $attacker['certificate']),
    ])->assertStatus(400);
});

/*
|--------------------------------------------------------------------------
| H — the EntityID is a permanent name, not a derived URL
|--------------------------------------------------------------------------
*/

it('freezes the EntityID at first publication while the endpoints follow the host', function (): void {
    config()->set('cbox-id.saml_idp.entity_id', null);
    config()->set('cbox-id.issuer', 'https://tenant.cboxid.test');

    $published = IdpDescriptor::entityId();
    expect($published)->toBe('https://tenant.cboxid.test/sso/saml/idp');

    // The tenant verifies a custom domain: the issuer legitimately moves.
    config()->set('cbox-id.issuer', 'https://id.customer.example');
    app()->forgetInstance(IssuerResolver::class);

    // The EntityID must NOT move with it — every SP that imported it would reject
    // the next assertion with "Issuer does not match", all at once.
    expect(IdpDescriptor::entityId())->toBe($published)
        // The endpoints do follow the host, which is what SAML expects.
        ->and(IdpDescriptor::ssoUrl())->toBe('https://id.customer.example/sso/saml/idp/sso')
        ->and(IdpDescriptor::sloUrl())->toBe('https://id.customer.example/sso/saml/idp/slo');
});

it('issues assertions under the frozen EntityID after the host moves', function (): void {
    config()->set('cbox-id.saml_idp.entity_id', null);
    config()->set('cbox-id.issuer', 'https://tenant.cboxid.test');

    $sp = $this->registerSamlServiceProvider();
    $frozen = IdpDescriptor::entityId();

    config()->set('cbox-id.issuer', 'https://id.customer.example');
    app()->forgetInstance(IssuerResolver::class);

    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id, destination: IdpDescriptor::ssoUrl()));
    $response = $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'a@sp.example.test']);

    expect($response->xml)->toContain('>'.$frozen.'</saml:Issuer>');
});

it('lets a configured EntityID override the frozen one', function (): void {
    config()->set('cbox-id.saml_idp.entity_id', 'urn:pinned:idp');

    expect(IdpDescriptor::entityId())->toBe('urn:pinned:idp');
});

/**
 * A Persistent NameID has to be opaque, and different at every service provider.
 *
 * SAML Core §8.3.7 defines the format as an opaque, SP-specific pseudonym — the whole
 * point being that two providers cannot match their users against each other. Ours was
 * whatever `name_id_attribute` pointed at, which defaults to `email`: the same value
 * everywhere, and PII rather than a pseudonym. The existing conformance tests asserted
 * the URN strings and the metadata, never the content, which is exactly how this
 * survived a conformance suite.
 */
it('issues an opaque, per-service-provider Persistent NameID', function (): void {
    $subject = 'user-persistent';

    $alpha = $this->registerSamlServiceProvider(
        entityId: 'https://alpha.example/metadata',
        acsUrl: 'https://alpha.example/acs',
        nameIdFormat: NameIdFormat::Persistent,
    );
    $beta = $this->registerSamlServiceProvider(
        entityId: 'https://beta.example/metadata',
        acsUrl: 'https://beta.example/acs',
        nameIdFormat: NameIdFormat::Persistent,
    );

    // A distinct request id per call: the IdP answers each AuthnRequest exactly once,
    // so a shared fixture id is refused as a replay on the second issuance.
    $issued = fn (ServiceProvider $sp, string $id): string => nameIdIn($this->samlIdp()->issueResponse(
        $this->samlIdp()->parseAuthnRequest(
            // The policy has to name the format the SP is registered with, or the
            // request is refused before a NameID is ever resolved.
            $this->makeRedirectAuthnRequest($sp->entity_id, $sp->acs_url, id: $id, nameIdFormat: NameIdFormat::Persistent->value),
            'state',
        ),
        $subject,
        ['email' => 'alice@corp.example'],
    )->xml);

    $toAlpha = $issued($alpha, '_req_alpha_one');
    $toBeta = $issued($beta, '_req_beta_one');

    expect($toAlpha)->not->toContain('alice@corp.example')
        ->and($toAlpha)->not->toContain($subject)
        ->and($toBeta)->not->toBe($toAlpha, 'two service providers received the same identifier for one person');

    // Stable for the SP that owns it — that is what "persistent" means.
    expect($issued($alpha, '_req_alpha_two'))
        ->toBe($toAlpha, 'the pseudonym changed between assertions to the same provider');
});

/**
 * And a Transient one must not be reused — §8.3.8 makes that a MUST NOT.
 */
it('mints a fresh Transient NameID for every assertion', function (): void {
    $sp = $this->registerSamlServiceProvider(
        entityId: 'https://transient.example/metadata',
        acsUrl: 'https://transient.example/acs',
        nameIdFormat: NameIdFormat::Transient,
    );

    $issued = fn (string $id): string => nameIdIn($this->samlIdp()->issueResponse(
        $this->samlIdp()->parseAuthnRequest(
            $this->makeRedirectAuthnRequest($sp->entity_id, $sp->acs_url, id: $id, nameIdFormat: NameIdFormat::Transient->value),
            'state',
        ),
        'user-transient',
        ['email' => 'bob@corp.example'],
    )->xml);

    $first = $issued('_req_transient_one');
    $second = $issued('_req_transient_two');

    expect($first)->not->toContain('bob@corp.example')
        ->and($second)->not->toBe($first, 'a transient identifier was reused across assertions');

    // Still resolvable for Single Logout: the value we sent is the value recorded.
    expect(SamlIdpSession::query()->where('name_id', $second)->exists())
        ->toBeTrue('a transient NameID was issued that logout could never resolve');
});

/**
 * The NameID as the service provider receives it — read out of the signed document,
 * never recomputed by the test. A conformance assertion that recalculates the value it
 * is checking proves only that the test agrees with itself.
 */
function nameIdIn(string $xml): string
{
    preg_match('/<saml:NameID[^>]*>([^<]+)<\/saml:NameID>/', $xml, $matches);

    return $matches[1] ?? '';
}

/**
 * ONE REPLAY NAMESPACE PER ENVIRONMENT, not one per deployment.
 *
 * An SP EntityID is chosen by the customer, so two tenants can legitimately register the
 * same one — `urn:federation:MicrosoftOnline` is not a hypothetical. Keyed on the SP alone,
 * tenant A claiming a message id made the SAME id arriving from tenant B's SP look like a
 * replay: a genuine sign-in refused, and deliberately causable by anybody who can send one
 * message to their own tenant.
 *
 * The SP-side store learned this already — `consumed_assertions` carries an
 * `environment_id` — and the IdP side never did.
 */
it('does not let one environment burn another environment\'s message ids', function (): void {
    $guard = app(MessageGuard::class);
    $environments = app(EnvironmentContext::class);

    $sp = 'urn:federation:MicrosoftOnline';
    $messageId = '_a-message-id-both-tenants-can-produce';

    $claimedInA = $environments->runAs(
        GenericEnvironment::of('env_tenant_a'),
        fn (): bool => $guard->consume($sp, $messageId, 300),
    );

    $claimedInB = $environments->runAs(
        GenericEnvironment::of('env_tenant_b'),
        fn (): bool => $guard->consume($sp, $messageId, 300),
    );

    expect($claimedInA)->toBeTrue()
        ->and($claimedInB)->toBeTrue('one tenant burned another tenant\'s message id');
})->group('security');

it('still refuses a replay within the same environment', function (): void {
    $guard = app(MessageGuard::class);
    $environments = app(EnvironmentContext::class);

    $result = $environments->runAs(GenericEnvironment::of('env_tenant_a'), fn (): array => [
        $guard->consume('urn:sp', '_replayed', 300),
        $guard->consume('urn:sp', '_replayed', 300),
    ]);

    expect($result[0])->toBeTrue()
        ->and($result[1])->toBeFalse('a replayed message id was claimed twice');
})->group('security');
