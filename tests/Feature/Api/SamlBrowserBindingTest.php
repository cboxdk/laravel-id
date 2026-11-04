<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Models\SamlAuthRequest;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Tests\Support\SamlIdp;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('requires the initiating browser cookie before accepting a signed SAML response', function (): void {
    $idp = new SamlIdp;
    $connections = app(Connections::class);
    $connection = $connections->create($this->makeOrganization()->id, ConnectionType::Saml, 'Corp SAML', [
        'idp_entity_id' => $idp->entityId,
        'idp_sso_url' => 'https://idp.example.test/sso',
        'idp_x509cert' => $idp->certPem,
        'sp_entity_id' => 'https://sp.example.test/metadata',
        'sp_acs_url' => 'https://localhost/sso/saml/acs',
    ]);
    $connections->activate($connection->organization_id, $connection->id);
    config(['session.domain' => '.example.test']);

    $started = $this->get('https://localhost/sso/saml/'.$connection->id.'/login')->assertRedirect();
    $cookie = collect($started->headers->getCookies())->first(fn ($cookie): bool => str_starts_with($cookie->getName(), '__Host-cbox_saml_'));
    expect($cookie)->not->toBeNull()
        ->and($cookie->getDomain())->toBeNull()
        ->and($cookie->getPath())->toBe('/')
        ->and($cookie->isSecure())->toBeTrue()
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->getSameSite())->toBe('none');

    $authRequest = SamlAuthRequest::query()->sole();
    $response = $idp->signedResponse('alice@example.test', 'https://sp.example.test/metadata', 'https://localhost/sso/saml/acs', inResponseTo: $authRequest->request_id);

    // Another browser knows the complete signed response, but has no cookie from login.
    $this->flushSession()->post('https://localhost/sso/saml/'.$connection->id.'/acs', ['SAMLResponse' => $response])->assertUnauthorized();
    expect($authRequest->fresh()?->consumed_at)->toBeNull();

    // A cross-site form POST has no Laravel session cookie; the dedicated cookie suffices.
    $accepted = $this->withUnencryptedCookie($cookie->getName(), (string) $cookie->getValue())
        ->post('https://localhost/sso/saml/'.$connection->id.'/acs', ['SAMLResponse' => $response])->assertOk();
    expect($authRequest->fresh()?->consumed_at)->not->toBeNull();
    $deleted = collect($accepted->headers->getCookies())->first(fn ($entry): bool => $entry->getName() === $cookie->getName());
    expect($deleted)->not->toBeNull()->and($deleted->getExpiresTime())->toBeLessThan(time());

    // Restoring a spent browser cookie cannot restore the server-side request.
    $this->post('https://localhost/sso/saml/'.$connection->id.'/acs', ['SAMLResponse' => $response])->assertUnauthorized();
})->group('security');

it('rejects OIDC connections at the SAML assertion endpoint before dispatching validation', function (): void {
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $private);
    $public = openssl_pkey_get_details($key)['key'];
    $connection = $this->makeConnection($this->makeOrganization()->id, ConnectionType::Oidc, 'OIDC', [
        'issuer' => 'https://idp.example.test',
        'client_id' => 'rp-client',
        'signing_key' => $public,
    ]);
    // A genuine ID token is valid for this connection, but has neither browser
    // state nor nonce. The SAML route must not provide a second OIDC login path.
    $token = JWT::encode([
        'iss' => 'https://idp.example.test',
        'aud' => 'rp-client',
        'sub' => 'oidc-subject',
        'email' => 'oidc@example.test',
        'iat' => time(),
        'exp' => time() + 300,
    ], $private, 'RS256');

    $this->post('/sso/saml/'.$connection->id.'/acs', ['SAMLResponse' => $token])
        ->assertNotFound();
    expect(Session::query()->count())->toBe(0);
})->group('security');
