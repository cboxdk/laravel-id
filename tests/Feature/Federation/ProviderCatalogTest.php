<?php

declare(strict_types=1);

use Cbox\Id\Federation\Enums\ClientSecretKind;
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

        // A parameter that does NOT appear in the issuer has to be credential material —
        // Apple asks for a team id, a key id and a signing key, none of which are part of
        // its issuer. Anything else is a value nobody consumes, which is the case this
        // half of the check exists to catch.
        $unused = array_values(array_diff($declared, $matches[1]));

        if ($template->secretKind === ClientSecretKind::Value) {
            expect($unused)->toBe([], $template->key.' asks for a value it never uses');
        }
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

/**
 * Apple is offered, but only because its shape is declared rather than assumed.
 *
 * Each of these three produces a failure that looks like something else: a secret stored
 * as a string works and then stops six months later; a GET handler never runs because
 * Apple POSTs its callback, which reads as the user cancelling; and a flow that discards
 * the first response has thrown away the only copy of the person's name that will ever
 * exist.
 */
it('declares what makes Apple different from every other entry', function (): void {
    $apple = ProviderCatalog::find('apple');

    expect($apple)->not->toBeNull()
        ->and($apple->secretKind)->toBe(ClientSecretKind::SignedJwt, 'Apple has no secret to paste')
        ->and($apple->responseMode)->toBe('form_post', 'Apple POSTs its callback once a scope beyond openid is asked for')
        ->and($apple->profileOnFirstAuthorizationOnly)->toBeTrue('Apple sends the name exactly once');

    // The key material it needs instead of a secret.
    $keys = array_map(fn ($p): string => $p->key, $apple->parameters);

    expect($keys)->toContain('team_id')->toContain('key_id')->toContain('private_key');

    // And nobody else should be claiming this shape by accident.
    foreach (ProviderCatalog::all() as $template) {
        if ($template->key === 'apple') {
            continue;
        }

        expect($template->secretKind)->toBe(ClientSecretKind::Value, $template->key.' claims a minted secret');
    }
});

it('offers Facebook as OAuth2, with an email that may simply not arrive', function (): void {
    $facebook = ProviderCatalog::find('facebook');

    expect($facebook?->protocol)->toBe(FederationProtocol::OAuth2)
        // Facebook does not tell us whether it verified the address, so the map must not
        // pretend it does — an absent claim is not a false one.
        ->and($facebook?->profile->emailVerified)->toBeNull();
});

it('marks GitHub and Discord as OAuth2, not OIDC', function (): void {
    // Neither publishes a discovery document or issues an id_token, so routing them
    // through the OIDC path fails at the first request with an unhelpful error.
    expect(ProviderCatalog::find('github')?->protocol)->toBe(FederationProtocol::OAuth2)
        ->and(ProviderCatalog::find('discord')?->protocol)->toBe(FederationProtocol::OAuth2)
        ->and(ProviderCatalog::find('google')?->protocol)->toBe(FederationProtocol::Oidc);
});
