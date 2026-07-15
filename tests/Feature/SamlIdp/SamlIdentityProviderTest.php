<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Sign the URL-encoded redirect-binding query the way an SP would, so we can drive
 * the signed-request path with a real RSA signature.
 *
 * @return array{cert: string, signature: callable(string, string): string}
 */
function spSigningKeypair(): array
{
    $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    expect($resource)->not->toBeFalse();

    $privatePem = '';
    openssl_pkey_export($resource, $privatePem);

    $csr = openssl_csr_new(['commonName' => 'sp.example.test'], $resource, ['digest_alg' => 'sha256']);
    $signed = openssl_csr_sign($csr, null, $resource, 365, ['digest_alg' => 'sha256'], 1);
    $certPem = '';
    openssl_x509_export($signed, $certPem);

    return [
        'cert' => $certPem,
        'signature' => function (string $samlRequest, string $sigAlg) use ($privatePem): string {
            $base = 'SAMLRequest='.urlencode($samlRequest).'&SigAlg='.urlencode($sigAlg);
            $signature = '';
            openssl_sign($base, $signature, $privatePem, OPENSSL_ALGO_SHA256);

            return base64_encode($signature);
        },
    ];
}

it('publishes IdP metadata with the signing certificate and SSO endpoints', function () {
    $metadata = $this->samlIdp()->metadata();

    expect($metadata)
        ->toContain('EntityDescriptor')
        ->toContain('IDPSSODescriptor')
        ->toContain('<md:SingleSignOnService')
        ->toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')
        ->toContain('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
        ->toContain('<ds:X509Certificate>')
        ->toContain(IdpDescriptor::entityId());
});

it('issues a signed assertion a real SP (onelogin) accepts, with correct audience, recipient, InResponseTo, NameID and attributes', function () {
    $sp = $this->registerSamlServiceProvider(
        entityId: 'https://sp.example.test/metadata',
        acsUrl: 'https://sp.example.test/acs',
        attributeMappings: ['email' => 'email', 'displayName' => 'name'],
    );

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id, $sp->acs_url);
    $request = $this->samlIdp()->parseAuthnRequest($samlRequest, 'return-here');

    $response = $this->samlIdp()->issueResponse($request, 'user-123', [
        'email' => 'alice@sp.example.test',
        'name' => 'Alice Example',
    ]);

    expect($response->acsUrl)->toBe('https://sp.example.test/acs');
    expect($response->relayState)->toBe('return-here');

    $material = app(IdpKeyMaterial::class)->active();

    [$oneLogin, $valid] = $this->validateWithOnelogin(
        $response->encoded,
        $sp,
        IdpDescriptor::entityId(),
        $material->certificatePem,
        $request->id,
    );

    expect($valid)->toBeTrue()
        ->and($oneLogin->getNameId())->toBe('alice@sp.example.test');

    $attributes = $oneLogin->getAttributes();
    expect($attributes['email'][0] ?? null)->toBe('alice@sp.example.test')
        ->and($attributes['displayName'][0] ?? null)->toBe('Alice Example');
});

it('produces an RSA-SHA256 signature and never SHA-1', function () {
    $sp = $this->registerSamlServiceProvider();
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));
    $response = $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'a@sp.example.test']);

    expect($response->xml)
        ->toContain('http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
        ->toContain('http://www.w3.org/2001/04/xmlenc#sha256')
        ->not->toContain('xmldsig#rsa-sha1')
        ->not->toContain('xmldsig#sha1');
});

it('is rejected by onelogin when the assertion is tampered after signing', function () {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));
    $response = $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'alice@sp.example.test']);

    // Flip an attribute value inside the signed document.
    $tampered = str_replace('alice@sp.example.test', 'attacker@evil.test', $response->xml);
    expect($tampered)->not->toBe($response->xml);

    $material = app(IdpKeyMaterial::class)->active();

    [, $valid] = $this->validateWithOnelogin(
        base64_encode($tampered),
        $sp,
        IdpDescriptor::entityId(),
        $material->certificatePem,
        $request->id,
    );

    expect($valid)->toBeFalse();
});

it('refuses an AuthnRequest whose ACS does not match the registered ACS', function () {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');

    $malicious = $this->makeRedirectAuthnRequest($sp->entity_id, 'https://attacker.test/steal');

    expect(fn () => $this->samlIdp()->parseAuthnRequest($malicious))
        ->toThrow(InvalidAuthnRequest::class);
});

it('refuses an AuthnRequest from an unregistered issuer', function () {
    $request = $this->makeRedirectAuthnRequest('https://unknown.test/metadata');

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request))
        ->toThrow(UnknownServiceProvider::class);
});

it('refuses an AuthnRequest from a disabled SP', function () {
    $sp = $this->registerSamlServiceProvider();
    $sp->forceFill(['status' => ServiceProviderStatus::Disabled])->save();

    expect(fn () => $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id)))
        ->toThrow(UnknownServiceProvider::class);
});

it('refuses a request carrying an XXE / DOCTYPE payload', function () {
    $this->registerSamlServiceProvider(entityId: 'https://sp.example.test/metadata');

    $xxe = '<?xml version="1.0"?><!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        .'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">'
        .'<saml:Issuer>https://sp.example.test/metadata&xxe;</saml:Issuer></samlp:AuthnRequest>';

    $encoded = base64_encode((string) gzdeflate($xxe));

    expect(fn () => $this->samlIdp()->parseAuthnRequest($encoded))
        ->toThrow(InvalidAuthnRequest::class);
});

it('rejects malformed base64 / XML', function () {
    expect(fn () => $this->samlIdp()->parseAuthnRequest('!!!not base64!!!'))
        ->toThrow(InvalidAuthnRequest::class);
});

it('accepts a correctly signed AuthnRequest when the SP requires signing', function () {
    $keypair = spSigningKeypair();

    $sp = $this->registerSamlServiceProvider(
        certificate: $keypair['cert'],
        wantAuthnRequestsSigned: true,
    );

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);
    $sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    $signature = $keypair['signature']($samlRequest, $sigAlg);

    $request = $this->samlIdp()->parseAuthnRequest($samlRequest, null, $signature, $sigAlg, true);

    expect($request->spEntityId)->toBe($sp->entity_id);
});

it('refuses an unsigned request when the SP requires signing', function () {
    $keypair = spSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['cert'], wantAuthnRequestsSigned: true);

    expect(fn () => $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id)))
        ->toThrow(InvalidAuthnRequest::class);
});

it('refuses a signed request that advertises SHA-1', function () {
    $keypair = spSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['cert'], wantAuthnRequestsSigned: true);

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);
    $sha1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    $signature = $keypair['signature']($samlRequest, $sha1);

    expect(fn () => $this->samlIdp()->parseAuthnRequest($samlRequest, null, $signature, $sha1, true))
        ->toThrow(InvalidAuthnRequest::class);
});

it('refuses a signed request whose signature does not verify', function () {
    $keypair = spSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['cert'], wantAuthnRequestsSigned: true);

    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);
    $sigAlg = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    // Sign a DIFFERENT payload so the signature is valid RSA but wrong for this request.
    $signature = $keypair['signature']('tampered-request', $sigAlg);

    expect(fn () => $this->samlIdp()->parseAuthnRequest($samlRequest, null, $signature, $sigAlg, true))
        ->toThrow(InvalidAuthnRequest::class);
});

it('accepts a correctly signed POST-binding AuthnRequest when the SP requires signing', function () {
    $keypair = $this->samlSigningKeypair();

    $sp = $this->registerSamlServiceProvider(
        certificate: $keypair['certificate'],
        wantAuthnRequestsSigned: true,
    );

    $samlRequest = $this->makeSignedPostAuthnRequest($sp->entity_id, $keypair['privateKey'], $keypair['certificate']);

    $request = $this->samlIdp()->parseAuthnRequest($samlRequest, null, null, null, false);

    expect($request->spEntityId)->toBe($sp->entity_id);
});

it('rejects a POST-binding request tampered after signing', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    $signed = (string) base64_decode($this->makeSignedPostAuthnRequest($sp->entity_id, $keypair['privateKey'], $keypair['certificate']), true);

    // Change the request ID (both the root attribute and the Reference URI, so the
    // signature stays structurally bound to the root) — the digest no longer matches
    // the signed content, so verification must fail.
    preg_match('/\sID="([^"]+)"/', $signed, $idMatch);
    $tampered = str_replace($idMatch[1], '_tampered000000000000000000000000000', $signed);
    expect($tampered)->not->toBe($signed);

    expect(fn () => $this->samlIdp()->parseAuthnRequest(base64_encode($tampered), null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class);
});

it('refuses an unsigned POST-binding request when the SP requires signing', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    // POST payloads are base64 only (no DEFLATE), and this one carries no signature.
    $unsigned = base64_encode($this->authnRequestXml($sp->entity_id));

    expect(fn () => $this->samlIdp()->parseAuthnRequest($unsigned, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class);
});

it('refuses a POST-binding request signed with SHA-1 (algorithm pin)', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    $sha1Request = $this->makeSignedPostAuthnRequest(
        $sp->entity_id,
        $keypair['privateKey'],
        $keypair['certificate'],
        signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
        digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    );

    expect(fn () => $this->samlIdp()->parseAuthnRequest($sha1Request, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class);
});

it('rejects an XML Signature Wrapping (XSW) POST request whose signature covers a decoy', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(
        certificate: $keypair['certificate'],
        wantAuthnRequestsSigned: true,
        acsUrl: 'https://sp.example.test/acs',
    );

    // A genuinely-signed request from this SP. Its signature covers the root (ID and
    // Reference URI generated by the signer).
    $legit = (string) base64_decode($this->makeSignedPostAuthnRequest($sp->entity_id, $keypair['privateKey'], $keypair['certificate']), true);
    $legit = (string) preg_replace('/^<\?xml[^>]*\?>/', '', $legit);

    // Lift the valid <ds:Signature> out, and keep the originally-signed root (minus
    // its signature) as a DECOY the signature still validates against.
    preg_match('/<ds:Signature\b.*<\/ds:Signature>/s', $legit, $sigMatch);
    $signature = $sigMatch[0];
    $decoy = str_replace($signature, '', $legit);

    // Wrap them under an attacker-controlled root the parser will actually read: the
    // lifted signature (still referencing the decoy's ID) is a direct child, and the
    // signed decoy is nested. onelogin's validateSign alone would accept this — the
    // binding check must reject it.
    $wrapped = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        .' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        .' ID="_attacker00000000000000000000000000000" Version="2.0" IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'">'
        .'<saml:Issuer>'.$sp->entity_id.'</saml:Issuer>'
        .$signature
        .$decoy
        .'</samlp:AuthnRequest>';

    expect(fn () => $this->samlIdp()->parseAuthnRequest(base64_encode($wrapped), null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class);
});

it('renders an auto-submitting POST form that escapes RelayState', function () {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), '"><script>alert(1)</script>');
    $response = $this->samlIdp()->issueResponse($request, 'user-1', ['email' => 'a@sp.example.test']);

    $form = $response->toPostForm();

    expect($form)
        ->toContain('action="https://sp.example.test/acs"')
        ->toContain('name="SAMLResponse"')
        ->toContain('document.forms[0].submit()')
        ->not->toContain('<script>alert(1)</script>');
});
