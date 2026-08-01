<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Cbox\Id\SamlIdp\Support\RedirectBindingResponseSigner;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OneLogin\Saml2\Utils as SamlUtils;

uses(RefreshDatabase::class);

const IDP_SLO_ENDPOINT = '/sso/saml/idp/slo';
const SP_SLO_URL = 'https://sp.example/saml/slo';

if (! function_exists('spKeypair')) {
    /**
     * A self-signed SP keypair: [privateKeyPem, certificatePem].
     *
     * @return array{0: string, 1: string}
     */
    function spKeypair(): array
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $privatePem);
        $csr = openssl_csr_new(['commonName' => 'sp.example'], $key, ['digest_alg' => 'sha256']);
        $x509 = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);
        openssl_x509_export($x509, $certPem);

        return [(string) $privatePem, (string) $certPem];
    }
}

if (! function_exists('registerSp')) {
    function registerSp(string $entityId, string $certPem, ?string $sloUrl = SP_SLO_URL): void
    {
        app(ServiceProviders::class)->register(new NewServiceProvider(
            entityId: $entityId,
            acsUrl: 'https://sp.example/saml/acs',
            nameIdFormat: NameIdFormat::EmailAddress,
            certificate: $certPem,
            wantAuthnRequestsSigned: true,
            sloUrl: $sloUrl,
        ));
    }
}

if (! function_exists('logoutRequestXml')) {
    /**
     * `$destination` defaults to the published SingleLogoutService endpoint — the
     * IdP validates it (SAML core §3.2.1 makes it a MUST on a signed message, and
     * every LogoutRequest here must be signed), so pass it explicitly to drive the
     * wrong-endpoint refusal. Pass '' to omit the attribute entirely.
     */
    function logoutRequestXml(string $entityId, string $id, ?string $issueInstant = null, ?string $destination = null): string
    {
        $destination ??= IdpDescriptor::sloUrl();

        return '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            .'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="'.$id.'" Version="2.0" '
            .'IssueInstant="'.($issueInstant ?? gmdate('Y-m-d\TH:i:s\Z')).'"'
            .($destination !== '' ? ' Destination="'.htmlspecialchars($destination, ENT_QUOTES).'"' : '').'>'
            .'<saml:Issuer>'.$entityId.'</saml:Issuer>'
            .'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test</saml:NameID>'
            .'</samlp:LogoutRequest>';
    }
}

if (! function_exists('signedRedirectQuery')) {
    /**
     * Build a signed HTTP-Redirect-binding query string for a message, via the same
     * signer the IdP uses for its responses (symmetric — request or response).
     *
     * @return array<string, string>
     */
    function signedRedirectQuery(string $xml, string $privateKeyPem, string $type, ?string $relayState = null): array
    {
        $url = (new RedirectBindingResponseSigner)->sign('https://placeholder', $xml, $relayState, $privateKeyPem, $type);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $params);

        /** @var array<string, string> $params */
        return $params;
    }
}

it('processes a signed LogoutRequest and returns a signed LogoutResponse to the SP', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $requestId = '_'.bin2hex(random_bytes(16));
    $query = signedRedirectQuery(logoutRequestXml($entityId, $requestId), $spPrivate, 'SAMLRequest', 'relay-xyz');

    $response = $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query));

    // 302 back to the SP's SLO endpoint, carrying a signed SAMLResponse.
    $response->assertRedirect();
    $location = (string) $response->headers->get('Location');
    expect($location)->toStartWith(SP_SLO_URL.'?');

    parse_str((string) parse_url($location, PHP_URL_QUERY), $out);
    /** @var array<string, string> $out */
    expect($out)->toHaveKeys(['SAMLResponse', 'SigAlg', 'Signature', 'RelayState'])
        ->and($out['RelayState'])->toBe('relay-xyz');

    // A real SP verifies the response signature against the IdP's published cert.
    $idpCert = app(IdpKeyMaterial::class)->active()->certificatePem;
    $valid = SamlUtils::validateBinarySign('SAMLResponse', $out, ['x509cert' => $idpCert]);
    expect($valid)->toBeTrue();

    // The response is a Success that echoes the request id via InResponseTo.
    $xml = (string) gzinflate((string) base64_decode($out['SAMLResponse'], true));
    expect($xml)->toContain('urn:oasis:names:tc:SAML:2.0:status:Success')
        ->and($xml)->toContain('InResponseTo="'.$requestId.'"')
        ->and($xml)->toContain('>'.IdpDescriptor::entityId().'</saml:Issuer>');
});

it('refuses a replayed LogoutRequest (one-time request id)', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $query = signedRedirectQuery(logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16))), $spPrivate, 'SAMLRequest');

    // First use succeeds; the identical (validly-signed) request replayed is refused.
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertRedirect();
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('refuses a stale LogoutRequest (IssueInstant outside the freshness window)', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $stale = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)), gmdate('Y-m-d\TH:i:s\Z', time() - 3600));
    $query = signedRedirectQuery($stale, $spPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('does NOT terminate the session when the LogoutRequest is invalid (no forced logout)', function (): void {
    $subject = $this->makeUser('victim@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($subject->id, null, ['pwd']);

    // A bogus SAMLRequest from a "logged-in" victim must be rejected BEFORE any
    // session teardown — otherwise a cross-site GET force-logs-them-out.
    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get(IDP_SLO_ENDPOINT.'?'.http_build_query(['SAMLRequest' => base64_encode((string) gzdeflate('not xml'))]))
        ->assertStatus(400);

    expect($sessions->active($session->id))->not->toBeNull();
});

it('refuses an unsigned LogoutRequest (the request is the security boundary)', function (): void {
    [, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $xml = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)));
    // Present a SAMLRequest with NO Signature/SigAlg at all.
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query([
        'SAMLRequest' => base64_encode((string) gzdeflate($xml)),
    ]))->assertStatus(400);
});

it('refuses a LogoutRequest signed by a key the SP did not register', function (): void {
    [, $spCert] = spKeypair();
    [$attackerPrivate] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $xml = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)));
    $query = signedRedirectQuery($xml, $attackerPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('refuses a signed LogoutRequest addressed to a different endpoint', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    // SAML bindings §3.5.5.2 makes verifying Destination a MUST on receipt, exactly
    // as on the SSO path. Without it, a LogoutRequest captured at another endpoint
    // (or another tenant's IdP) replays here inside its freshness window and forces
    // a logout.
    $xml = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)), destination: 'https://other-idp.test/slo');
    $query = signedRedirectQuery($xml, $spPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('refuses a signed LogoutRequest that carries no Destination at all', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $xml = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)), destination: '');
    $query = signedRedirectQuery($xml, $spPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('refuses a LogoutRequest from an unregistered service provider', function (): void {
    [$spPrivate] = spKeypair();

    $xml = logoutRequestXml('https://stranger.example/metadata', '_'.bin2hex(random_bytes(16)));
    $query = signedRedirectQuery($xml, $spPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('refuses when the SP registered no SLO endpoint to answer', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert, sloUrl: null);

    $xml = logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16)));
    $query = signedRedirectQuery($xml, $spPrivate, 'SAMLRequest');

    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertStatus(400);
});

it('does a plain local logout when no SAMLRequest is present', function (): void {
    $this->get(IDP_SLO_ENDPOINT)->assertOk()->assertSee('Signed out', false);
});

/**
 * A service provider may end a session it was given, and only that.
 *
 * This test used to name Alice in a LogoutRequest from an SP that had never seen her, and
 * expect her session revoked — it encoded the vulnerability. The controller resolved the
 * NameID as a subject id OR an email and revoked everything, so any registered SP could
 * sign a request naming any user (an email is not a secret) and end their day, over and
 * over, for people it had no relationship with.
 *
 * The realistic flow is the one below: we issued an assertion for Alice to this SP, so
 * the SP knows her under that name and may log her out of it.
 */
it('revokes the named subject sessions on a valid SP-initiated SLO', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    // Alice (the NameID in the request) has a live session. The browser hitting the
    // SLO endpoint is NOT logged in as Alice — the IdP must still revoke HER session,
    // keyed off the verified NameID, not auth()->id().
    $alice = $this->makeUser('alice@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($alice->id, null, ['pwd']);

    // The state issuing an assertion leaves behind: this SP was told about Alice.
    SamlIdpSession::query()->create([
        'sp_entity_id' => $entityId,
        'subject_id' => $alice->id,
        'name_id' => 'alice@example.test',
        'session_index' => '_'.bin2hex(random_bytes(16)),
        'expires_at' => now()->addDay(),
    ]);

    $query = signedRedirectQuery(logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16))), $spPrivate, 'SAMLRequest');
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertRedirect();

    expect($sessions->active($session->id))->toBeNull();
});

/**
 * And a service provider that was never told about her cannot touch her.
 *
 * The signature is valid and the SP is registered — an admin added it — so nothing else
 * in the pipeline refuses this. Only the issued-session record does.
 */
it('refuses to log out a subject the requesting SP was never given', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $alice = $this->makeUser('alice@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($alice->id, null, ['pwd']);

    // No SamlIdpSession record: this SP has never received an assertion for Alice.
    $query = signedRedirectQuery(logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16))), $spPrivate, 'SAMLRequest');
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertRedirect();

    expect($sessions->active($session->id))
        ->not->toBeNull('a service provider logged out a user it had never seen');
});

/**
 * Nor can one SP log out a subject that a DIFFERENT SP was given. Same NameID, same
 * subject, wrong relying party.
 */
it('refuses a logout for a name another service provider was given', function (): void {
    [$spPrivate, $spCert] = spKeypair();
    $entityId = 'https://sp.example/metadata';
    registerSp($entityId, $spCert);

    $alice = $this->makeUser('alice@example.test');
    $sessions = app(SessionManager::class);
    $session = $sessions->start($alice->id, null, ['pwd']);

    SamlIdpSession::query()->create([
        'sp_entity_id' => 'https://someone-else.example/metadata',
        'subject_id' => $alice->id,
        'name_id' => 'alice@example.test',
        'session_index' => '_'.bin2hex(random_bytes(16)),
        'expires_at' => now()->addDay(),
    ]);

    $query = signedRedirectQuery(logoutRequestXml($entityId, '_'.bin2hex(random_bytes(16))), $spPrivate, 'SAMLRequest');
    $this->get(IDP_SLO_ENDPOINT.'?'.http_build_query($query))->assertRedirect();

    expect($sessions->active($session->id))
        ->not->toBeNull('one service provider logged out a session belonging to another');
});
