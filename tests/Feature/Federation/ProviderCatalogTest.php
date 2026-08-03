<?php

declare(strict_types=1);

use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;

/**
 * The catalogue is data, and data that is wrong is worse than data that is missing: a
 * wrong issuer sends an administrator to a provider's own error page and tells them
 * nothing about which side is at fault.
 *
 * These are the invariants that keep an entry from being added carelessly.
 */
it('gives every provider a unique key and a name', function (): void {
    $keys = ProviderCatalog::keys();

    expect($keys)->not->toBeEmpty()
        ->and(array_unique($keys))->toBe($keys, 'two providers share a key, so one shadows the other');

    foreach (ProviderCatalog::all() as $template) {
        expect($template->name)->not->toBe('', $template->key.' has no display name');
    }
});

it('gives every OIDC provider an issuer and every OAuth2 provider its endpoints', function (): void {
    foreach (ProviderCatalog::all() as $template) {
        if ($template->isOidc()) {
            expect($template->issuerTemplate)->not->toBeNull($template->key.' is OIDC with no issuer');

            continue;
        }

        // There is no discovery for these, so anything missing here is only discovered
        // by a person standing in a redirect.
        expect($template->authorizationEndpoint)->not->toBeNull($template->key.' has no authorization endpoint')
            ->and($template->tokenEndpoint)->not->toBeNull($template->key.' has no token endpoint')
            ->and($template->profileEndpoint)->not->toBeNull($template->key.' has no profile endpoint')
            ->and($template->issuerTemplate)->toBeNull($template->key.' is OAuth2 but claims an issuer');
    }
});

it('declares a parameter for every placeholder in an issuer template', function (): void {
    foreach (ProviderCatalog::all() as $template) {
        if ($template->issuerTemplate === null) {
            continue;
        }

        preg_match_all('/\{([a-z_]+)\}/', $template->issuerTemplate, $matches);

        $declared = array_map(fn ($p): string => $p->key, $template->parameters);

        expect(array_values(array_diff($matches[1], $declared)))
            ->toBe([], $template->key.' has a placeholder nobody can fill in');

        expect(array_values(array_diff($declared, $matches[1])))
            ->toBe([], $template->key.' asks for a value it never uses');
    }
});

/**
 * The point of the catalogue is that an administrator does not have to know anything the
 * provider did not tell them. An entry with no steps is an entry that has not been
 * finished.
 */
it('tells an administrator how to obtain the credential', function (): void {
    foreach (ProviderCatalog::all() as $template) {
        expect($template->setupSteps)->not->toBeEmpty($template->key.' has no setup steps')
            ->and($template->documentationUrl)->not->toBeNull($template->key.' links to no documentation');
    }
});

/**
 * A subject that its owner can change is a subject someone else can inherit. GitHub
 * usernames and Discord handles are both re-claimable, which is why neither may be the
 * identifier an account is linked by.
 */
it('never links an account by a value its owner can change', function (): void {
    $unstable = ['login', 'username', 'email', 'preferred_username', 'name', 'global_name', 'handle'];

    foreach (ProviderCatalog::all() as $template) {
        expect(in_array($template->profile->subject, $unstable, true))
            ->toBeFalse($template->key.' links accounts by '.$template->profile->subject.', which its owner can change');
    }
});

it('requests the scopes its profile map depends on', function (): void {
    $github = ProviderCatalog::find('github');

    expect($github)->toBeInstanceOf(ProviderTemplate::class)
        // Without user:email the address is unavailable for anyone who has not made it
        // public — which is the default, so most sign-ins would arrive with no email.
        ->and($github->scopes)->toContain('user:email')
        ->and($github->profile->emailEndpoint)->not->toBeNull();
});

it('resolves an issuer only once every parameter is supplied', function (): void {
    $entra = ProviderCatalog::find('microsoft');

    expect($entra?->issuerFor([]))->toBeNull('a half-substituted issuer would pass a URL validator and fail at discovery')
        ->and($entra?->issuerFor(['directory' => '72f988bf-86f1-41af-91ab-2d7cd011db47']))
        ->toBe('https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0');

    // A provider with nothing to fill in resolves immediately.
    expect(ProviderCatalog::find('google')?->issuerFor([]))->toBe('https://accounts.google.com');
});

it('does not offer Apple, whose secret is a JWT rather than a value', function (): void {
    // Deliberate: Apple's "client secret" is a JWT the relying party signs and re-mints
    // every six months. Listing it beside Google would promise a text field can hold it.
    expect(ProviderCatalog::find('apple'))->toBeNull();
});

it('marks GitHub and Discord as OAuth2, not OIDC', function (): void {
    // Neither publishes a discovery document or issues an id_token, so routing them
    // through the OIDC path fails at the first request with an unhelpful error.
    expect(ProviderCatalog::find('github')?->protocol)->toBe(FederationProtocol::OAuth2)
        ->and(ProviderCatalog::find('discord')?->protocol)->toBe(FederationProtocol::OAuth2)
        ->and(ProviderCatalog::find('google')?->protocol)->toBe(FederationProtocol::Oidc);
});
