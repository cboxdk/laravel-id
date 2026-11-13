<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\Subject;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\SamlStatusCode;
use Cbox\Id\SamlIdp\Exceptions\EmailNotVerified;
use Cbox\Id\SamlIdp\Exceptions\SubjectNotPermitted;
use Cbox\Id\SamlIdp\Models\SamlIdpSession;
use Cbox\Id\SamlIdp\ValueObjects\SamlResponse;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * THE IDP NEVER ASSERTS AN EMAIL ADDRESS NOBODY VERIFIED.
 *
 * A SAML assertion is a signed statement relying parties act on, and most SPs key their
 * accounts by the email in the NameID or in an `email` attribute. issueResponse() takes
 * the attributes from its caller, so the rule lives in the IdP itself: a host that hands
 * it an unconfirmed address must not get it signed.
 */

function samlEmailSubject(string $email, bool $verified): Subject
{
    $subjects = app(Subjects::class);
    $subject = $subjects->create($email, 'Pat Example');

    if ($verified) {
        $subjects->markEmailVerified($subject->id, $email);
    }

    return $subject;
}

function assertionXml(SamlResponse $response): string
{
    return (string) base64_decode($response->encoded, true);
}

it('refuses to assert an unverified email as the NameID', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider(attributeMappings: ['displayName' => 'name']);
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id), 'relay-1');

    try {
        $this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'pat@example.test', 'name' => 'Pat Example']);
        $this->fail('an assertion carrying an unverified email was issued');
    } catch (EmailNotVerified $refused) {
        $error = $refused->samlError();

        expect($refused)->toBeInstanceOf(SubjectNotPermitted::class)
            ->and($error?->status)->toBe(SamlStatusCode::Responder)
            ->and($error?->subStatus)->toBe(SamlStatusCode::RequestDenied)
            ->and($error?->acsUrl)->toBe($sp->acs_url)
            ->and($error?->inResponseTo)->toBe($request->id)
            ->and($error?->relayState)->toBe('relay-1');
    }

    expect(SamlIdpSession::query()->count())->toBe(0);

    $entry = AuditEntry::query()->where('action', 'saml_idp.assertion_refused')->first();
    expect($entry?->context['reason'] ?? null)->toBe('email_not_verified');
})->group('security');

it('refuses an unspecified NameID sourced from an unverified email', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider(attributeMappings: [], nameIdFormat: NameIdFormat::Unspecified);
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: null));

    expect(fn () => $this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'pat@example.test']))
        ->toThrow(EmailNotVerified::class);
})->group('security');

it('refuses to release an unverified email through an attribute mapping', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider(attributeMappings: ['mail' => 'email'], nameIdFormat: NameIdFormat::Persistent);
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: null));

    expect(fn () => $this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'pat@example.test']))
        ->toThrow(EmailNotVerified::class);
})->group('security');

it('refuses even when the caller does not pass the email, if the SP would receive it', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider();
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));

    expect(fn () => $this->samlIdp()->issueResponse($request, $subject->id, ['name' => 'Pat Example']))
        ->toThrow(EmailNotVerified::class);
})->group('security');

it('refuses an email the caller supplies that is not the subject\'s verified address', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: true);
    $sp = $this->registerSamlServiceProvider();
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));

    expect(fn () => $this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'someone-else@example.test']))
        ->toThrow(EmailNotVerified::class);
})->group('security');

it('refuses an email for a subject the resolver does not know', function (): void {
    $sp = $this->registerSamlServiceProvider();
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));

    expect(fn () => $this->samlIdp()->issueResponse($request, 'no-such-subject', ['email' => 'pat@example.test']))
        ->toThrow(EmailNotVerified::class);
})->group('security');

it('signs an unverified person in to an SP that never receives the email, without the address', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider(
        attributeMappings: ['displayName' => 'name', 'contact' => 'contact'],
        nameIdFormat: NameIdFormat::Persistent,
    );
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: null));

    // The address arrives under another field name too; it is dropped there as well.
    $xml = assertionXml($this->samlIdp()->issueResponse($request, $subject->id, [
        'email' => 'pat@example.test',
        'contact' => 'PAT@example.test',
        'name' => 'Pat Example',
    ]));

    expect($xml)->toContain('Pat Example')
        ->not->toContain('pat@example.test')
        ->not->toContain('PAT@example.test');
})->group('security');

it('lets the same request through once the address is verified', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider();
    $request = $this->samlIdp()->parseAuthnRequest($this->makeRedirectAuthnRequest($sp->entity_id));

    expect(fn () => $this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'pat@example.test']))
        ->toThrow(EmailNotVerified::class);

    app(Subjects::class)->markEmailVerified($subject->id, 'pat@example.test');

    $xml = assertionXml($this->samlIdp()->issueResponse($request, $subject->id, ['email' => 'pat@example.test']));

    expect($xml)->toContain('pat@example.test');
})->group('security');

it('tells an unverified person at the SSO endpoint to confirm their address, and issues nothing', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider();

    $response = $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $this->makeRedirectAuthnRequest($sp->entity_id)]));

    $response->assertForbidden();
    expect((string) $response->getContent())->toContain('Confirm your email address')
        ->not->toContain('SAMLResponse')
        ->not->toContain('pat@example.test');
    expect(SamlIdpSession::query()->count())->toBe(0);
})->group('security');

it('keeps an unverified email out of the SSO endpoint\'s assertion for an SP that does not receive it', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: false);
    $sp = $this->registerSamlServiceProvider(attributeMappings: ['displayName' => 'name'], nameIdFormat: NameIdFormat::Persistent);

    $html = (string) $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $this->makeRedirectAuthnRequest($sp->entity_id, nameIdFormat: null)]))
        ->assertOk()
        ->getContent();

    preg_match('/name="SAMLResponse" value="([^"]+)"/', $html, $matches);
    $xml = (string) base64_decode($matches[1] ?? '', true);

    expect($xml)->toContain('Pat Example')->not->toContain('pat@example.test');
})->group('security');

it('asserts a verified email at the SSO endpoint', function (): void {
    $subject = samlEmailSubject('pat@example.test', verified: true);
    $sp = $this->registerSamlServiceProvider();

    $html = (string) $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->get('/sso/saml/idp/sso?'.http_build_query(['SAMLRequest' => $this->makeRedirectAuthnRequest($sp->entity_id)]))
        ->assertOk()
        ->getContent();

    preg_match('/name="SAMLResponse" value="([^"]+)"/', $html, $matches);

    expect((string) base64_decode($matches[1] ?? '', true))->toContain('pat@example.test');
});
