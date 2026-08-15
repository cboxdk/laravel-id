<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\UnknownServiceProvider;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;
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

/**
 * THE ONLY XXE TEST IN THIS PACKAGE, and it was passing for the wrong reason.
 *
 * `IssueInstant` was hardcoded to a fixed date that has since gone stale, so the request
 * was refused by the freshness check long before anything looked at the DOCTYPE — and
 * `InvalidAuthnRequest` is the single rejection class for every reason on this path, so
 * removing the entity guard entirely left this green. A current timestamp plus the
 * guard's own message is what makes it about XXE.
 */
it('refuses a request carrying an XXE / DOCTYPE payload', function () {
    $this->registerSamlServiceProvider(entityId: 'https://sp.example.test/metadata');

    $xxe = '<?xml version="1.0"?><!DOCTYPE samlp:AuthnRequest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        .'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="'
        .gmdate('Y-m-d\TH:i:s\Z').'">'
        .'<saml:Issuer>https://sp.example.test/metadata&xxe;</saml:Issuer></samlp:AuthnRequest>';

    $encoded = base64_encode((string) gzdeflate($xxe));

    expect(fn () => $this->samlIdp()->parseAuthnRequest($encoded))
        ->toThrow(InvalidAuthnRequest::class, 'malformed or unsafe XML');
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

/**
 * ONE ALGORITHM AT A TIME, and the message asserted.
 *
 * This flipped signature AND digest together and asserted the exception CLASS — which is
 * the single rejection type for every reason on this path. Deleting either pin left the
 * other throwing the same class, so neither could be observed alone and the test would
 * have kept passing with half the control gone. The builder already takes the two
 * independently.
 */
it('refuses a POST-binding request whose SIGNATURE is RSA-SHA1', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    $request = $this->makeSignedPostAuthnRequest(
        $sp->entity_id,
        $keypair['privateKey'],
        $keypair['certificate'],
        signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
    );

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class, 'unsupported signature algorithm (RSA-SHA256 required)');
});

it('refuses a POST-binding request whose DIGEST is SHA-1, signature notwithstanding', function () {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(certificate: $keypair['certificate'], wantAuthnRequestsSigned: true);

    $request = $this->makeSignedPostAuthnRequest(
        $sp->entity_id,
        $keypair['privateKey'],
        $keypair['certificate'],
        digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
    );

    expect(fn () => $this->samlIdp()->parseAuthnRequest($request, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class, 'unsupported digest algorithm (SHA-256 required)');
});

/**
 * Build an attacker-controlled root carrying a lifted, still-valid signature.
 *
 * `Destination` matters and is the reason this suite once proved nothing: without it the
 * parser rejects the wrapper at an unrelated check long before the binding checks run,
 * and since InvalidAuthnRequest is the single exception class for EVERY rejection reason,
 * a test asserting only the class passed with the whole XSW defence deleted. Every case
 * below asserts the MESSAGE.
 *
 * @param  callable(string, string): string  $assemble  (signature, decoy) => inner XML
 */
function wrappedAuthnRequest(string $entityId, string $legit, callable $assemble, string $rootId = '_attacker00000000000000000000000000000'): string
{
    preg_match('/<ds:Signature\b.*<\/ds:Signature>/s', $legit, $sigMatch);
    $signature = $sigMatch[0];
    $decoy = str_replace($signature, '', $legit);

    return base64_encode(
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
        .' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        .' ID="'.$rootId.'" Version="2.0" IssueInstant="'.gmdate('Y-m-d\TH:i:s\Z').'"'
        .' Destination="'.IdpDescriptor::ssoUrl().'">'
        .'<saml:Issuer>'.$entityId.'</saml:Issuer>'
        .$assemble($signature, $decoy)
        .'</samlp:AuthnRequest>'
    );
}

/**
 * XML Signature Wrapping against the IdP's front door: an SP whose certificate we trust
 * lifts its own valid signature onto a request root it controls. onelogin's validateSign
 * alone accepts this, because the signature really does verify — against the decoy it
 * still references. The binding checks are the only thing that notices.
 *
 * If these ever pass with EmbeddedSignature neutered, the IdP accepts forged
 * AuthnRequests from any SP it trusts.
 *
 * @param  callable(string, string): string  $assemble
 */
it('rejects a wrapped AuthnRequest', function (callable $assemble, string $expected) {
    $keypair = $this->samlSigningKeypair();
    $sp = $this->registerSamlServiceProvider(
        certificate: $keypair['certificate'],
        wantAuthnRequestsSigned: true,
        acsUrl: 'https://sp.example.test/acs',
    );

    $legit = (string) base64_decode($this->makeSignedPostAuthnRequest($sp->entity_id, $keypair['privateKey'], $keypair['certificate']), true);
    $legit = (string) preg_replace('/^<\?xml[^>]*\?>/', '', $legit);

    $wrapped = wrappedAuthnRequest($sp->entity_id, $legit, $assemble);

    expect(fn () => $this->samlIdp()->parseAuthnRequest($wrapped, null, null, null, false))
        ->toThrow(InvalidAuthnRequest::class, $expected);
})->with([
    // The classic: signature a direct child of the attacker root, still referencing the
    // decoy's ID. Caught by the Reference-URI binding.
    'signature at the root, reference on the decoy' => [
        fn (string $signature, string $decoy): string => $signature.$decoy,
        'does not cover the request root',
    ],
    // Hidden one level deeper, so there is no root-child signature at all. Caught a
    // layer earlier than the other two — hasEmbeddedSignature() also looks only at root
    // children, so the request reads as unsigned and is refused for a connection that
    // requires signing. Asserting the message it ACTUALLY produces rather than the one
    // I expected: two independent checks agreeing is the point, and a test that lies
    // about which one fired is how the previous version of this file passed with the
    // whole defence deleted.
    'signature buried below the root' => [
        fn (string $signature, string $decoy): string => '<samlp:Extensions>'.$signature.'</samlp:Extensions>'.$decoy,
        'a signed AuthnRequest is required',
    ],
    // Two root children: a real one and a decoy. A checker that takes the first match
    // rather than requiring exactly one would be fooled.
    'two signatures on the root' => [
        fn (string $signature, string $decoy): string => $signature.$signature.$decoy,
        'exactly one enveloped signature on the request root',
    ],
]);

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

/**
 * Issuing an assertion records who we told, and under what name.
 *
 * Single Logout has no other way to know. Without this record it took the NameID from a
 * signed LogoutRequest and revoked every session of whoever it resolved to — and a NameID
 * is not a secret, so any registered service provider could name any user and end their
 * day. The record is what turns "someone signed this" into "this SP may log out this
 * person".
 *
 * The SessionIndex is the value already minted into the AuthnStatement and previously
 * thrown away; recording it is what will let a conformant SP end ONE session rather than
 * all of them.
 */
it('records the issued assertion so logout can be scoped to the service provider', function () {
    $sp = $this->registerSamlServiceProvider(acsUrl: 'https://sp.example.test/acs');

    $request = $this->samlIdp()->parseAuthnRequest(
        $this->makeRedirectAuthnRequest($sp->entity_id, $sp->acs_url),
    );

    $response = $this->samlIdp()->issueResponse($request, 'user-recorded', ['email' => 'recorded@example.test']);

    expect($response->encoded)->not->toBe('');

    $record = SamlIdpSession::query()->where('subject_id', 'user-recorded')->first();

    expect($record)->not->toBeNull('nothing recorded what we told the service provider')
        ->and($record->sp_entity_id)->toBe($sp->entity_id)
        ->and($record->name_id)->toBe('recorded@example.test')
        ->and($record->session_index)->not->toBe('')
        // The same index that went into the assertion, or an SP's per-session logout
        // would name something we never sent.
        ->and(base64_decode($response->encoded, true))->toContain($record->session_index);
});
