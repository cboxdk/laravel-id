<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\MembershipStatus;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\SamlIdp\Contracts\IdpKeyMaterial;
use Cbox\Id\SamlIdp\Enums\SamlStatusCode;
use Cbox\Id\SamlIdp\Exceptions\InvalidAuthnRequest;
use Cbox\Id\SamlIdp\Exceptions\SubjectNotPermitted;
use Cbox\Id\SamlIdp\SamlIdentityProviderService;
use Cbox\Id\SamlIdp\Support\IdpDescriptor;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * An organization-owned SAML service provider is that organization's app.
 *
 * Every SP used to be environment-wide in effect: the IdP never asked whether the subject
 * it was about to assert had anything to do with the SP's owner, so anybody who could sign
 * in to the environment could single-sign-on into any organization's SAML app.
 */

it('asserts an active member of the owning organization, and names the organization', function (): void {
    $org = $this->makeOrganization('Northwind');
    $member = $this->makeUser('member@northwind.test');
    app(Memberships::class)->add($org->id, $member->id, MembershipRole::Member);

    $sp = $this->registerSamlServiceProvider(organizationId: $org->id);
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));

    $response = $this->samlIdp()->issueResponse($request, $member->id, ['email' => 'member@northwind.test', 'name' => 'M']);

    [$oneLogin, $valid] = $this->validateWithOnelogin(
        $response->encoded,
        $sp,
        IdpDescriptor::entityId(),
        app(IdpKeyMaterial::class)->active()->certificatePem,
        $request->id,
    );

    expect($valid)->toBeTrue()
        ->and($oneLogin->getAttributes()[SamlIdentityProviderService::ORGANIZATION_ATTRIBUTE][0] ?? null)->toBe($org->id);
})->group('security');

it('refuses a subject who is not a member of the owning organization', function (): void {
    $owner = $this->makeOrganization('Northwind');
    $other = $this->makeOrganization('Contoso');
    $outsider = $this->makeUser('outsider@contoso.test');
    app(Memberships::class)->add($other->id, $outsider->id, MembershipRole::Owner);

    $sp = $this->registerSamlServiceProvider(organizationId: $owner->id);
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), 'relay-1');

    try {
        $this->samlIdp()->issueResponse($request, $outsider->id, ['email' => 'outsider@contoso.test']);
        $this->fail('an assertion was issued to a non-member');
    } catch (SubjectNotPermitted $refused) {
        // Reported to the SP in SAML, on its registered ACS, answering its request.
        $error = $refused->samlError();

        expect($refused)->toBeInstanceOf(InvalidAuthnRequest::class)
            ->and($error?->status)->toBe(SamlStatusCode::Responder)
            ->and($error?->subStatus)->toBe(SamlStatusCode::RequestDenied)
            ->and($error?->acsUrl)->toBe($sp->acs_url)
            ->and($error?->inResponseTo)->toBe($request->id)
            ->and($error?->relayState)->toBe('relay-1');
    }

    // Audited on the OWNING organization's trail, and announced on its bus.
    $entry = AuditEntry::query()->where('action', 'saml_idp.assertion_refused')->first();

    expect($entry)->not->toBeNull()
        ->and($entry?->organization_id)->toBe($owner->id)
        ->and($entry?->actor_id)->toBe($outsider->id)
        ->and($entry?->target_id)->toBe($sp->id)
        ->and(Event::query()->where('type', 'saml_idp.assertion_refused')->where('organization_id', $owner->id)->exists())->toBeTrue();

    // Refused BEFORE the request id was burned: a member can still answer it.
    $member = $this->makeUser('member@northwind.test');
    app(Memberships::class)->add($owner->id, $member->id, MembershipRole::Member);

    expect($this->samlIdp()->issueResponse($request, $member->id, ['email' => 'member@northwind.test'])->acsUrl)
        ->toBe($sp->acs_url);
})->group('security');

it('refuses a suspended member of the owning organization', function (): void {
    $org = $this->makeOrganization('Northwind');
    $member = $this->makeUser('suspended@northwind.test');
    app(Memberships::class)->add($org->id, $member->id, MembershipRole::Member);
    Membership::query()->withoutGlobalScopes()->where('user_id', $member->id)->update(['status' => MembershipStatus::Suspended->value]);

    $sp = $this->registerSamlServiceProvider(organizationId: $org->id);

    expect(fn () => $this->samlIdp()->issueResponse($this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), 'relay-1'), $member->id, ['email' => 'suspended@northwind.test']))
        ->toThrow(SubjectNotPermitted::class);
})->group('security');

it('keeps an environment-wide service provider open to any subject, without an organization attribute', function (): void {
    $this->makeOrganization('Northwind');
    $anyone = $this->makeUser('anyone@example.test');

    $sp = $this->registerSamlServiceProvider();

    expect($sp->organization_id)->toBeNull();

    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), 'relay-1');
    $response = $this->samlIdp()->issueResponse($request, $anyone->id, ['email' => 'anyone@example.test']);

    [$oneLogin, $valid] = $this->validateWithOnelogin(
        $response->encoded,
        $sp,
        IdpDescriptor::entityId(),
        app(IdpKeyMaterial::class)->active()->certificatePem,
        $request->id,
    );

    expect($valid)->toBeTrue()
        ->and($oneLogin->getAttributes())->not->toHaveKey(SamlIdentityProviderService::ORGANIZATION_ATTRIBUTE)
        ->and(AuditEntry::query()->where('action', 'saml_idp.assertion_refused')->exists())->toBeFalse();
});

it('does not let an attribute mapping overwrite the organization attribute', function (): void {
    $org = $this->makeOrganization('Northwind');
    $member = $this->makeUser('member@northwind.test');
    app(Memberships::class)->add($org->id, $member->id, MembershipRole::Member);

    $sp = $this->registerSamlServiceProvider(
        attributeMappings: ['email' => 'email', SamlIdentityProviderService::ORGANIZATION_ATTRIBUTE => 'claimed_org'],
        organizationId: $org->id,
    );

    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), 'relay-1');
    $response = $this->samlIdp()->issueResponse($request, $member->id, [
        'email' => 'member@northwind.test',
        'claimed_org' => 'someone-elses-org',
    ]);

    expect($response->xml)->toContain($org->id)->not->toContain('someone-elses-org');
})->group('security');

it('answers a non-member at the SSO endpoint with a SAML RequestDenied, not an assertion or a 500', function (): void {
    $org = $this->makeOrganization('Northwind');
    $outsider = $this->makeUser('outsider@example.test');
    $sp = $this->registerSamlServiceProvider(organizationId: $org->id);

    $html = (string) $this->actingAs(new GenericUser(['id' => $outsider->id, 'remember_token' => '']))
        ->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $this->makeRedirectAuthnRequest($sp->entity_id)]))
        ->assertOk()
        ->getContent();

    preg_match('/name="SAMLResponse" value="([^"]+)"/', $html, $matches);
    $xml = (string) base64_decode($matches[1] ?? '', true);

    expect($xml)->toContain(SamlStatusCode::RequestDenied->value)
        ->not->toContain('<saml:Assertion');
})->group('security');
