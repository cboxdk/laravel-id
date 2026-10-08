<?php

declare(strict_types=1);

use Cbox\Id\Federation\Enums\GuideProtocol;
use Cbox\Id\Federation\Enums\GuideReturnKind;
use Cbox\Id\Federation\Enums\ProviderCapability;
use Cbox\Id\Federation\Enums\SpValue;
use Cbox\Id\Federation\IdentityProviderGuides;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\GuideField;
use Cbox\Id\Federation\ValueObjects\IdentityProviderGuide;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Cbox\Id\Federation\ValueObjects\ScimDirectoryGuide;
use Cbox\Id\Federation\ValueObjects\ServiceProviderValues;

/*
 * The enterprise IdP guides are data an administrator follows on a screen we do not
 * control. A wrong label sends them hunting for a field that does not exist, and a guide
 * that forgets our ACS URL produces a connection that fails at the first sign-in. These
 * are the invariants that keep an entry from being added carelessly — plus spot checks
 * of labels that were verified against the vendors' own documentation.
 */

/** @return list<GuideField> */
function guideRequired(IdentityProviderGuide $guide): array
{
    return $guide->requiredFields();
}

function guideAsksRequired(IdentityProviderGuide $guide, SpValue $value): bool
{
    foreach (guideRequired($guide) as $field) {
        if ($field->ours === $value) {
            return true;
        }
    }

    return false;
}

it('covers the identity providers administrators run, under unique keys', function (): void {
    $keys = IdentityProviderGuides::keys();

    expect(array_unique($keys))->toBe($keys, 'two guides share a key, so one shadows the other')
        ->and($keys)->toBe([
            'okta', 'entra', 'google', 'onelogin', 'jumpcloud', 'pingfederate', 'pingone', 'adfs', 'auth0', 'keycloak',
            'duo', 'cyberark', 'shibboleth', 'oracle', 'sap', 'salesforce', 'lastpass', 'cloudflare', 'saml', 'oidc',
        ]);

    foreach (IdentityProviderGuides::all() as $guide) {
        expect($guide->name)->not->toBe('', $guide->key.' has no display name')
            ->and(IdentityProviderGuides::find($guide->key))->toEqual($guide);
    }

    expect(IdentityProviderGuides::find('nope'))->toBeNull();
});

/**
 * The minimum a connection needs: for SAML, where to post the assertion and who it is
 * for — either typed in, or carried by our metadata for an IdP that imports it; for
 * OIDC, where to send the browser back.
 */
it('asks every guide for the values its protocol cannot work without', function (): void {
    foreach (IdentityProviderGuides::all() as $guide) {
        if ($guide->protocol === GuideProtocol::Oidc) {
            expect(guideAsksRequired($guide, SpValue::RedirectUri))->toBeTrue($guide->key.' never asks for our redirect URI')
                ->and($guide->returns->kind)->toBe(GuideReturnKind::Oidc, $guide->key.' is OIDC but brings back SAML metadata');

            continue;
        }

        $typed = guideAsksRequired($guide, SpValue::AcsUrl) && guideAsksRequired($guide, SpValue::EntityId);
        $imported = $guide->asksFor(SpValue::SpMetadataUrl);

        expect($typed || $imported)->toBeTrue($guide->key.' asks for neither our ACS URL and entity ID nor our metadata URL')
            ->and($guide->returns->kind)->not->toBe(GuideReturnKind::Oidc, $guide->key.' is SAML but brings back OIDC credentials');

        // An IdP that only imports our metadata must make that the REQUIRED step.
        if (! $typed) {
            expect(guideAsksRequired($guide, SpValue::SpMetadataUrl))->toBeTrue($guide->key.' relies on our metadata but marks it optional');
        }
    }
});

it('names every field and every return, and links only to https documentation', function (): void {
    foreach (IdentityProviderGuides::all() as $guide) {
        $fields = [...$guide->fields, ...($guide->directory->fields ?? [])];

        foreach ($fields as $field) {
            expect(trim($field->theirs))->not->toBe('', $guide->key.' has a field with no label');

            if ($field->ours === SpValue::Literal) {
                expect($field->literal)->not->toBeNull()->not->toBe('');
            } else {
                expect($field->literal)->toBeNull($guide->key.' carries a literal on '.$field->ours->value);
            }
        }

        expect(trim($guide->returns->theirs))->not->toBe('', $guide->key.' does not say what to bring back')
            ->and($guide->setupSteps)->not->toBeEmpty($guide->key.' has no steps');

        foreach ([$guide->documentationUrl, $guide->directory?->documentationUrl] as $url) {
            if ($url !== null) {
                expect($url)->toStartWith('https://');
            }
        }

        // A named vendor without its documentation is a guide nobody can check; only the
        // two generic guides have no vendor to link to.
        if (! in_array($guide->key, ['saml', 'oidc'], true)) {
            expect($guide->documentationUrl)->not->toBeNull($guide->key.' links to no vendor documentation');
        }
    }
});

/**
 * A SCIM push cannot start without our base URL and our bearer token. Oracle asks for
 * the URL in two halves, which counts.
 */
it('gives every SCIM directory guide our base URL and our token', function (): void {
    $directories = IdentityProviderGuides::directories();

    expect(array_map(static fn (IdentityProviderGuide $g): string => $g->key, $directories))
        ->toBe(['okta', 'entra', 'onelogin', 'jumpcloud', 'pingfederate', 'pingone', 'duo', 'cyberark', 'oracle']);

    foreach ([...array_map(static fn (IdentityProviderGuide $g): ?ScimDirectoryGuide => $g->directory, $directories), IdentityProviderGuides::genericDirectory()] as $directory) {
        expect($directory)->toBeInstanceOf(ScimDirectoryGuide::class);

        $url = $directory->asksFor(SpValue::ScimBaseUrl)
            || ($directory->asksFor(SpValue::ScimHost) && $directory->asksFor(SpValue::ScimBasePath));

        expect($url)->toBeTrue('a directory guide never asks for our SCIM URL')
            ->and($directory->asksFor(SpValue::ScimToken))->toBeTrue('a directory guide never asks for our token')
            ->and($directory->setupSteps)->not->toBeEmpty();
    }
});

/**
 * The reason this is a separate catalogue. Anything ProviderCatalog::withCapability(Login)
 * returns can become a sign-in button; an enterprise IdP must never be one of them.
 */
it('keeps enterprise identity providers off the sign-in buttons', function (): void {
    $buttons = array_map(static fn (ProviderTemplate $t): string => $t->key, ProviderCatalog::withCapability(ProviderCapability::Login));

    foreach (['entra', 'onelogin', 'jumpcloud', 'pingfederate', 'pingone', 'adfs', 'duo', 'cyberark', 'shibboleth', 'oracle', 'sap', 'salesforce', 'lastpass', 'cloudflare', 'saml', 'oidc'] as $key) {
        expect($buttons)->not->toContain($key);
    }

    expect(ProviderCatalog::enterpriseGuides())->toEqual(IdentityProviderGuides::all());
});

it('spells the labels the way each vendor\'s screen does', function (): void {
    $theirs = static fn (string $key, SpValue $ours): array => array_map(
        static fn (GuideField $f): string => $f->theirs,
        array_values(array_filter(IdentityProviderGuides::find($key)->fields ?? [], static fn (GuideField $f): bool => $f->ours === $ours)),
    );

    expect($theirs('okta', SpValue::AcsUrl))->toBe(['Single sign-on URL'])
        ->and($theirs('okta', SpValue::EntityId))->toBe(['Audience URI (SP Entity ID)'])
        ->and($theirs('entra', SpValue::AcsUrl))->toBe(['Reply URL (Assertion Consumer Service URL)'])
        ->and($theirs('entra', SpValue::EntityId))->toBe(['Identifier (Entity ID)'])
        // OneLogin wants the ACS URL twice — as the Recipient and as the ACS itself.
        ->and($theirs('onelogin', SpValue::AcsUrl))->toBe(['Recipient', 'ACS (Consumer) URL'])
        // The apostrophe is the curly one PingFederate prints.
        ->and($theirs('pingfederate', SpValue::EntityId))->toBe(['Partner’s Entity ID (Connection ID)'])
        ->and($theirs('adfs', SpValue::AcsUrl))->toBe(['Relying party SAML 2.0 SSO service URL'])
        ->and($theirs('oracle', SpValue::AcsUrl))->toBe(['Assertion consumer URL']);

    expect(IdentityProviderGuides::find('entra')?->directory?->fields[0]->theirs)->toBe('Tenant URL')
        ->and(IdentityProviderGuides::find('entra')?->directory?->fields[1]->theirs)->toBe('Secret Token')
        ->and(IdentityProviderGuides::find('okta')?->returns->theirs)->toBe('Metadata URL')
        ->and(IdentityProviderGuides::find('keycloak')?->protocol)->toBe(GuideProtocol::Oidc);

    // Two fields PingFederate calls "Endpoint URL" are told apart by where they sit.
    $endpoints = array_values(array_filter(
        IdentityProviderGuides::find('pingfederate')->fields ?? [],
        static fn (GuideField $f): bool => $f->theirs === 'Endpoint URL',
    ));

    expect($endpoints)->toHaveCount(2)
        ->and($endpoints[0]->location)->not->toBe($endpoints[1]->location);
});

it('fills each field from the connection\'s values, deriving the two that are derived', function (): void {
    $values = new ServiceProviderValues(
        acsUrl: 'https://id.acme.test/sso/saml/01J/acs',
        entityId: 'https://id.acme.test/sso/saml/01J/metadata',
        scimBaseUrl: 'https://id.acme.test/scim/v2',
        scimToken: 'scim_tok',
    );

    $onelogin = IdentityProviderGuides::find('onelogin');
    $validator = array_values(array_filter($onelogin->fields ?? [], static fn (GuideField $f): bool => $f->ours === SpValue::AcsUrlPattern))[0];

    // The regex OneLogin's validator wants: anchored, every metacharacter escaped —
    // computed exactly as the hosted console has always computed it (preg_quote).
    expect($validator->valueFrom($values))->toBe('^https\:\/\/id\.acme\.test\/sso\/saml\/01J\/acs$')
        ->and(preg_match('/'.$validator->valueFrom($values).'/', 'https://id.acme.test/sso/saml/01J/acs'))->toBe(1)
        ->and(preg_match('/'.$validator->valueFrom($values).'/', 'https://id.acme.test/sso/saml/01J/acs/extra'))->toBe(0);

    // Oracle asks for our SCIM URL as host and path.
    $oracle = IdentityProviderGuides::find('oracle')?->directory;
    $byOurs = [];

    foreach ($oracle->fields ?? [] as $field) {
        $byOurs[$field->ours->value] = $field->valueFrom($values);
    }

    expect($byOurs)->toBe(['scim_host' => 'id.acme.test', 'scim_base_path' => '/scim/v2', 'scim_token' => 'scim_tok']);

    // A literal is the same for everybody; a value the host did not supply is null.
    $okta = IdentityProviderGuides::find('okta');

    expect($okta->fields[2]->valueFrom($values))->toBe('EmailAddress')
        ->and((new ServiceProviderValues)->for(SpValue::AcsUrlPattern))->toBeNull()
        ->and(SpValue::ScimToken->isSecret())->toBeTrue()
        ->and(SpValue::AcsUrl->isSecret())->toBeFalse();
});

it('refuses a field that would tell an administrator nothing', function (): void {
    expect(fn () => new GuideField(SpValue::AcsUrl, '  '))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GuideField(SpValue::Literal, 'Name ID format'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new GuideField(SpValue::AcsUrl, 'ACS URL', 'https://ignored.test'))->toThrow(InvalidArgumentException::class);
});

it('groups guides by protocol', function (): void {
    expect(array_map(static fn (IdentityProviderGuide $g): string => $g->key, IdentityProviderGuides::forProtocol(GuideProtocol::Oidc)))
        ->toBe(['keycloak', 'oidc'])
        ->and(GuideProtocol::Saml->connectionType()->value)->toBe('saml');
});
