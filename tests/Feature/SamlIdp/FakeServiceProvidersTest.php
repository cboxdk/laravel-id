<?php

declare(strict_types=1);

use Cbox\Id\SamlIdp\Contracts\ServiceProviders;
use Cbox\Id\SamlIdp\Enums\NameIdFormat;
use Cbox\Id\SamlIdp\Enums\ServiceProviderStatus;
use Cbox\Id\SamlIdp\Models\ServiceProvider;
use Cbox\Id\SamlIdp\Testing\FakeServiceProviders;
use Cbox\Id\SamlIdp\Testing\InteractsWithSamlIdp;
use Cbox\Id\SamlIdp\ValueObjects\NewServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * {@see FakeServiceProviders} ships to consumers but had no exercise of its own. A
 * host app that swaps it in is trusting behaviour nobody checks — in particular the
 * deny-by-default `findActiveByEntityId`, which is the method the assertion path
 * actually calls. These tests bind it the way its own docblock tells consumers to,
 * then drive it through the shipped
 * {@see InteractsWithSamlIdp} helper.
 */
beforeEach(function (): void {
    app()->instance(ServiceProviders::class, new FakeServiceProviders);
});

it('registers a service provider through the shipped trait helper', function (): void {
    $sp = $this->registerSamlServiceProvider(
        entityId: 'https://sp.example.test/metadata',
        acsUrl: 'https://sp.example.test/acs',
        attributeMappings: ['email' => 'email', 'displayName' => 'name'],
    );

    expect($sp)->toBeInstanceOf(ServiceProvider::class)
        ->and($sp->id)->toBeString()->not->toBe('')
        ->and($sp->entity_id)->toBe('https://sp.example.test/metadata')
        ->and($sp->acs_url)->toBe('https://sp.example.test/acs')
        ->and($sp->attribute_mappings)->toBe(['email' => 'email', 'displayName' => 'name'])
        ->and($sp->name_id_format)->toBe(NameIdFormat::EmailAddress)
        ->and($sp->status)->toBe(ServiceProviderStatus::Active);
});

it('keeps everything in memory — no service_providers row is ever persisted', function (): void {
    // The whole point of the fake: exercise the IdP without the package's tables.
    $this->registerSamlServiceProvider();

    expect(ServiceProvider::query()->count())->toBe(0);
});

it('finds a registered provider by entity id, by id, and lists them all', function (): void {
    $first = $this->registerSamlServiceProvider(entityId: 'https://a.test/metadata', acsUrl: 'https://a.test/acs');
    $second = $this->registerSamlServiceProvider(entityId: 'https://b.test/metadata', acsUrl: 'https://b.test/acs');

    $registry = app(ServiceProviders::class);

    expect($registry->findByEntityId('https://a.test/metadata')?->id)->toBe($first->id)
        ->and($registry->findById($second->id)?->entity_id)->toBe('https://b.test/metadata')
        ->and($registry->all()->pluck('entity_id')->all())
        ->toBe(['https://a.test/metadata', 'https://b.test/metadata']);
});

it('returns null for an unknown entity id or id, rather than a stub provider', function (): void {
    $registry = app(ServiceProviders::class);

    expect($registry->findByEntityId('https://never-registered.test/metadata'))->toBeNull()
        ->and($registry->findById('01HZZZZZZZZZZZZZZZZZZZZZZZ'))->toBeNull()
        ->and($registry->findActiveByEntityId('https://never-registered.test/metadata'))->toBeNull()
        ->and($registry->all())->toBeEmpty();
});

it('mirrors the real registry\'s deny-by-default: a disabled provider is found but never active', function (): void {
    // findActiveByEntityId is the method the assertion path calls, so a fake that
    // returned a disabled SP here would let a host app ship a suite that "passes"
    // while the real IdP refuses every login.
    //
    // NOTE for maintainers: registerSamlServiceProvider() cannot express a disabled
    // provider, so reaching this state means bypassing the shipped helper.
    $registry = app(ServiceProviders::class);
    $disabled = $registry->register(new NewServiceProvider(
        entityId: 'https://disabled.test/metadata',
        acsUrl: 'https://disabled.test/acs',
        status: ServiceProviderStatus::Disabled,
    ));

    expect($registry->findByEntityId('https://disabled.test/metadata')?->id)->toBe($disabled->id)
        ->and($registry->findActiveByEntityId('https://disabled.test/metadata'))->toBeNull();
});

it('carries the signature and NameID settings a relying SP registers with', function (): void {
    $keypair = $this->samlSigningKeypair('sp.example.test');

    $sp = $this->registerSamlServiceProvider(
        entityId: 'https://signed.test/metadata',
        acsUrl: 'https://signed.test/acs',
        certificate: $keypair['certificate'],
        wantAuthnRequestsSigned: true,
        nameIdFormat: NameIdFormat::Persistent,
        nameIdAttribute: 'sub',
    );

    expect($sp->want_authn_requests_signed)->toBeTrue()
        ->and($sp->certificate)->toBe($keypair['certificate'])
        ->and($sp->name_id_format)->toBe(NameIdFormat::Persistent)
        ->and($sp->name_id_attribute)->toBe('sub');
});

it('keeps both records when the same entity id is registered twice, and resolves to the first', function (): void {
    // Two registrations of one entity id are two distinct records here (the fake is
    // keyed by model id), and lookup by entity id resolves to the first — worth
    // pinning so a consumer knows what to expect rather than discovering it.
    $registry = app(ServiceProviders::class);
    $first = $this->registerSamlServiceProvider(entityId: 'https://dup.test/metadata', acsUrl: 'https://dup.test/acs-1');
    $this->registerSamlServiceProvider(entityId: 'https://dup.test/metadata', acsUrl: 'https://dup.test/acs-2');

    expect($registry->all())->toHaveCount(2)
        ->and($registry->findByEntityId('https://dup.test/metadata')?->id)->toBe($first->id);
});
