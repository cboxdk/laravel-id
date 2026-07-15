<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('serves IdP metadata over HTTP without leaking the literal idp connection route', function () {
    $response = $this->get('/sso/saml/idp/metadata');

    $response->assertOk();
    expect($response->headers->get('Content-Type'))->toContain('application/samlmetadata+xml');
    expect($response->getContent())->toContain('IDPSSODescriptor');
});

it('hands off to 401 when no subject is authenticated and no login_url is configured', function () {
    $sp = $this->registerSamlServiceProvider();
    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);

    $response = $this->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $samlRequest]));

    $response->assertStatus(401);
});

it('redirects to the configured host login carrying return_to when unauthenticated', function () {
    config()->set('cbox-id.saml_idp.login_url', 'https://app.test/login');

    $sp = $this->registerSamlServiceProvider();
    $samlRequest = $this->makeRedirectAuthnRequest($sp->entity_id);

    $response = $this->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $samlRequest]));

    $response->assertRedirect();
    expect($response->headers->get('Location'))
        ->toStartWith('https://app.test/login')
        ->toContain('return_to=');
});

it('rejects an SSO request for an unknown SP at the endpoint', function () {
    $samlRequest = $this->makeRedirectAuthnRequest('https://stranger.test/metadata');

    $response = $this->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $samlRequest]));

    $response->assertStatus(403);
});

it('rejects an SSO request with a missing SAMLRequest', function () {
    $response = $this->get('/sso/saml/idp/sso');

    $response->assertStatus(400);
});
