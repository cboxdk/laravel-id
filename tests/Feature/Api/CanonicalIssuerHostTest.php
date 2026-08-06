<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Models\Environment;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

/**
 * @group security
 *
 * What the canonical-host redirect covers, and — the part that had no test at all — what
 * it must NOT touch.
 *
 * The redirect exists for one reason: RFC 8414 §3.3 makes the published `issuer` equal to
 * the URL the document was fetched from a MUST, so an alias of an environment cannot serve
 * metadata naming the other host. That argument reaches metadata and stops there. Applied
 * to the whole IdP surface it broke three things at once, none of which any assertion in
 * this suite would have caught:
 *
 *  - the back channel authenticates by CREDENTIAL, and HTTP clients drop `Authorization`
 *    across origins — so a redirect turned a provisioning call into a 401 rather than
 *    moving it. SCIM has no issuer concept whatsoever;
 *  - `form-action` is enforced across the entire redirect chain, so an SP whose CSP names
 *    only the alias has the BROWSER block a cross-host 308 on the SAML POST binding;
 *  - a 301 is heuristically cacheable with no freshness information (RFC 9111 §4.2.2), so
 *    a tenant that later clears its custom domain strands every client that saw one.
 */
beforeEach(fn () => config([
    'cbox-id.environments.base_domains' => ['cboxid.com'],
    'cbox-id.issuer' => 'https://cboxid.com',
]));

/** A tenant reachable at BOTH its `{slug}.{base}` alias and its verified custom domain. */
function tenantOnTwoHosts(): Environment
{
    return Environment::create([
        'name' => 'Acme',
        'slug' => 'acme',
        'domain' => 'id.acme.com',
        'domain_verified_at' => now(),
        'is_default' => false,
    ]);
}

it('sends metadata on the alias to the host the document names', function (): void {
    tenantOnTwoHosts();

    $this->get('https://acme.cboxid.com/.well-known/openid-configuration')
        ->assertRedirect('https://id.acme.com/.well-known/openid-configuration');
});

it('never lets a metadata redirect be cached, so a cleared domain is recoverable', function (): void {
    tenantOnTwoHosts();

    // The failure mode this guards: `EnvironmentDomainService::clear()` reverts `domain`
    // to null, at which point the alias IS canonical again — but a browser that cached a
    // permanent redirect keeps sending the tenant to a host that no longer resolves, and
    // there is nothing the operator can do to unwind it. 302 says "not permanent";
    // no-store says "do not keep this at all".
    $response = $this->get('https://acme.cboxid.com/.well-known/openid-configuration');

    expect($response->getStatusCode())->toBe(302)
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');
});

it('keeps SCIM provisioning working on the alias', function (): void {
    $tenant = tenantOnTwoHosts();

    $directory = $this->runAsEnvironment(
        $tenant->id,
        fn () => $this->makeDirectory($this->makeOrganization('Acme Inc')->id),
    );

    $headers = ['Authorization' => 'Bearer '.$directory->token];

    // The regression in full: Okta and Entra were configured against the alias before the
    // tenant ever verified a custom domain, and a connector follows a 3xx WITHOUT
    // re-attaching `Authorization` to the new origin. Every request in the import
    // therefore became an unauthenticated one and the connector reported a hard failure.
    // A 201 here is the property; a 302 would be the outage.
    $id = $this->postJson('https://acme.cboxid.com/scim/v2/Users', [
        'userName' => 'dana',
        'externalId' => 'okta|1',
        'emails' => [['value' => 'dana@acme.com', 'primary' => true]],
        'active' => true,
    ], $headers)->assertStatus(201)->json('id');

    // …including the writes, which is where a method-preserving 308 would have landed.
    $this->patchJson('https://acme.cboxid.com/scim/v2/Users/'.$id, [
        'Operations' => [['op' => 'replace', 'value' => ['active' => false]]],
    ], $headers)->assertOk()->assertJsonPath('active', false);
});

it('serves the credential-bearing back channel on the alias rather than bouncing it', function (): void {
    tenantOnTwoHosts();

    // Asserted as "the ENDPOINT answered", not merely "not a redirect": each status below
    // is the ordinary refusal that endpoint gives a request carrying no credential (400
    // for a token request with no grant, 401 for the bearer- and secret-authenticated
    // ones), so only the endpoint itself can have produced it. The absent Location is the
    // second half — a 308 was what shipped, and it carried one.
    $unmoved = [
        [$this->post('https://acme.cboxid.com/oauth/token'), 400],
        [$this->post('https://acme.cboxid.com/oauth/introspect'), 401],
        [$this->post('https://acme.cboxid.com/oauth/revoke'), 401],
        [$this->get('https://acme.cboxid.com/oauth/userinfo'), 401],
        [$this->get('https://acme.cboxid.com/scim/v2/Users'), 401],
        [$this->patch('https://acme.cboxid.com/scim/v2/Users/abc'), 401],
    ];

    foreach ($unmoved as [$response, $status]) {
        expect($response->headers->get('Location'))->toBeNull()
            ->and($response->getStatusCode())->toBe($status);
    }
})->group('security');

it('does not redirect the SAML POST binding, which a relying SP CSP would block', function (): void {
    tenantOnTwoHosts();

    // `form-action` applies to every hop of a redirect chain, so an SP that lists only
    // `acme.cboxid.com` has the browser refuse the navigation to `id.acme.com` — a
    // failure with no server-side trace at all. The endpoint answering for itself (400
    // for an AuthnRequest that is not there) is the property.
    $response = $this->post('https://acme.cboxid.com/sso/saml/idp/sso');

    expect($response->headers->get('Location'))->toBeNull()
        ->and($response->getStatusCode())->toBe(400);
})->group('security');

it('leaves the canonical host itself alone', function (): void {
    tenantOnTwoHosts();

    $this->get('https://id.acme.com/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://id.acme.com');
});

it('leaves an environment with no host identity of its own on every host it answers', function (): void {
    // The platform root and every single-tenant / on-prem deployment inherit a configured,
    // host-independent issuer — so an internal load-balancer name or a second ingress is a
    // legitimate way to reach them, not an alias to be corrected.
    Environment::create(['name' => 'Root', 'slug' => 'root', 'is_default' => true]);

    $this->get('https://internal-lb.cluster.local/.well-known/openid-configuration')
        ->assertOk()
        ->assertJsonPath('issuer', 'https://cboxid.com');
});
