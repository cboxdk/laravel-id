<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $org = $this->makeOrganization();
    $this->scimHeaders = ['Authorization' => 'Bearer '.$this->makeDirectory($org->id)->token];
});

it('publishes ServiceProviderConfig with PATCH and filter support', function (): void {
    $this->getJson('/scim/v2/ServiceProviderConfig', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('patch.supported', true)
        ->assertJsonPath('filter.supported', true)
        ->assertJsonPath('authenticationSchemes.0.type', 'oauthbearertoken');
});

/**
 * `documentationUri` is OPTIONAL in RFC 7643 §5, and it used to be hard-coded to
 * `<app>/docs` — a route this package does not register. Connectors that surface the
 * link during setup (Okta shows it) therefore sent the operator to a 404. Omitting an
 * optional field is correct; publishing a broken one is a promise the deployment cannot
 * keep, so the absence is pinned rather than left to chance.
 */
it('omits documentationUri when the host publishes no SCIM help page', function (): void {
    config()->set('cbox-id.scim.documentation_uri', null);

    $this->getJson('/scim/v2/ServiceProviderConfig', $this->scimHeaders)
        ->assertOk()
        ->assertJsonMissingPath('documentationUri');
});

it('publishes documentationUri when the host configures one', function (): void {
    config()->set('cbox-id.scim.documentation_uri', 'https://docs.example.test/scim');

    $this->getJson('/scim/v2/ServiceProviderConfig', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('documentationUri', 'https://docs.example.test/scim');
});

it('publishes the User resource type', function (): void {
    $this->getJson('/scim/v2/ResourceTypes', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('Resources.0.endpoint', '/Users')
        ->assertJsonPath('Resources.0.schema', 'urn:ietf:params:scim:schemas:core:2.0:User');
});

it('publishes the User schema with a server-unique userName', function (): void {
    $this->getJson('/scim/v2/Schemas', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('Resources.0.id', 'urn:ietf:params:scim:schemas:core:2.0:User')
        ->assertJsonPath('Resources.0.attributes.0.name', 'userName')
        ->assertJsonPath('Resources.0.attributes.0.uniqueness', 'server');
});

it('advertises the Enterprise User extension on the User resource type', function (): void {
    $this->getJson('/scim/v2/ResourceTypes', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('Resources.0.schemaExtensions.0.schema', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User')
        ->assertJsonPath('Resources.0.schemaExtensions.0.required', false);
});

it('publishes the Enterprise User schema', function (): void {
    $this->getJson('/scim/v2/Schemas', $this->scimHeaders)
        ->assertOk()
        ->assertJsonPath('Resources.1.id', 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User')
        ->assertJsonPath('Resources.1.name', 'EnterpriseUser')
        ->assertJsonFragment(['name' => 'department']);
});

it('requires the directory bearer token for discovery', function (): void {
    $this->getJson('/scim/v2/ServiceProviderConfig')->assertStatus(401);
});
