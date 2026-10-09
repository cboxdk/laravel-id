<?php

declare(strict_types=1);

use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Pipes\Exceptions\InvalidPipeConfiguration;
use Cbox\Id\Pipes\PipeProviderCatalog;
use Cbox\Id\Pipes\ValueObjects\PipeProvider;

it('offers the eight providers the product promises, each once', function (): void {
    expect(PipeProviderCatalog::keys())->toBe(['github', 'google', 'microsoft', 'slack', 'salesforce', 'hubspot', 'linear', 'notion']);
});

it('only ever talks to providers over https', function (PipeProvider $provider): void {
    $values = $provider->parameterValues([]);

    foreach ([$provider->authorizationEndpoint, $provider->tokenEndpoint, $provider->accountEndpoint, $provider->revocation?->endpoint] as $endpoint) {
        if ($endpoint === null) {
            continue;
        }

        expect($provider->endpoint($endpoint, $values, ['client_id' => 'c', 'refresh_token' => 'r']))->toStartWith('https://');
    }

    expect($provider->documentationUrl)->toStartWith('https://')
        ->and($provider->setupSteps)->not->toBeEmpty();
})->with(fn (): array => array_map(fn (PipeProvider $p): array => [$p], PipeProviderCatalog::all()));

it('reads what it shares with the sign-in catalogue from the sign-in catalogue', function (): void {
    // One fact, one place: GitHub's endpoints and the vendor names are not restated.
    $github = PipeProviderCatalog::find('github');
    $signIn = ProviderCatalog::find('github');

    expect($github?->authorizationEndpoint)->toBe($signIn?->authorizationEndpoint)
        ->and($github?->tokenEndpoint)->toBe($signIn?->tokenEndpoint)
        ->and($github?->name)->toBe($signIn?->name)
        ->and(PipeProviderCatalog::find('google')?->name)->toBe(ProviderCatalog::find('google')?->name);

    foreach (PipeProviderCatalog::all() as $provider) {
        if ($provider->signInKey !== null) {
            expect(ProviderCatalog::find($provider->signInKey))->not->toBeNull();
        }
    }
});

it('substitutes per-installation parameters, falling back to a default that works', function (): void {
    $microsoft = PipeProviderCatalog::find('microsoft');

    expect($microsoft?->endpoint($microsoft->tokenEndpoint, []))
        ->toBe('https://login.microsoftonline.com/common/oauth2/v2.0/token')
        ->and($microsoft?->endpoint($microsoft->tokenEndpoint, ['tenant' => 'contoso.onmicrosoft.com']))
        ->toBe('https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token');

    $salesforce = PipeProviderCatalog::find('salesforce');

    expect($salesforce?->endpoint($salesforce->tokenEndpoint, ['domain' => 'test.salesforce.com']))
        ->toBe('https://test.salesforce.com/services/oauth2/token');
});

it('refuses a parameter that would point the client secret somewhere else', function (string $provider, array $values): void {
    $entry = PipeProviderCatalog::find($provider);

    expect(fn () => $entry?->parameterValues($values))->toThrow(InvalidPipeConfiguration::class);
})->with([
    'a host outside salesforce' => ['salesforce', ['domain' => 'evil.test']],
    'a lookalike suffix' => ['salesforce', ['domain' => 'login.salesforce.com.evil.test']],
    'a path in the tenant' => ['microsoft', ['tenant' => 'contoso/../../evil']],
    'a parameter the provider does not have' => ['github', ['host' => 'evil.test']],
]);
