<?php

declare(strict_types=1);

use Cbox\Id\Directory\DirectoryConnectors;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Directory\Exceptions\IncompleteHrisCredentials;
use Cbox\Id\Directory\Hris\Contracts\HrisProvider;
use Cbox\Id\Directory\Hris\HrisCatalog;
use Cbox\Id\Directory\Hris\ValueObjects\HrisSyncOptions;
use Cbox\Id\Federation\ProviderCatalog;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Sleep;

/**
 * The HR-system catalogue and the connectors are one contract: a setup form built from the
 * catalogue must collect exactly what the connector reads.
 */
beforeEach(function (): void {
    Sleep::fake();
    Http::fake([
        '*/ccx/oauth2/*' => Http::response(['access_token' => 'wd']),
        '*/ccx/service/customreport2/*' => Http::response(['Report_Entry' => []]),
        '*.bamboohr.com/*' => Http::response(['data' => [], 'meta' => ['page' => ['nextCursor' => null]]]),
        'rest.ripplingapis.com/*' => Http::response(['results' => [], 'next_link' => null]),
        'api.hibob.com/*' => Http::response(['employees' => [], 'items' => []]),
        'api.personio.de/v2/auth/token' => Http::response(['access_token' => 'p']),
        'api.personio.de/*' => Http::response(['_data' => [], '_meta' => ['links' => []]]),
    ]);
});

it('has a catalogue entry and a registered connector for every HR system, and none for anything else', function (): void {
    $connectors = app(DirectoryConnectors::class);

    foreach (DirectoryProvider::cases() as $provider) {
        expect(HrisCatalog::for($provider) !== null)->toBe($provider->isHris(), $provider->value)
            ->and($provider->isHris() ? $provider->isPull() : true)->toBeTrue();

        if ($provider->isHris()) {
            expect($connectors->has($provider))->toBeTrue()
                ->and($connectors->for($provider))->toBeInstanceOf(HrisProvider::class)
                // Never a sign-in provider: nothing in the federation catalogue claims it.
                ->and(ProviderCatalog::forDirectory($provider))->toBeNull();
        }
    }

    expect(array_map(fn ($s) => $s->provider, HrisCatalog::all()))->toBe(DirectoryProvider::hris());
});

it('gives every HR system steps, documentation, and marks its secrets', function (): void {
    foreach (HrisCatalog::all() as $setup) {
        expect($setup->setupSteps)->not->toBeEmpty()
            ->and($setup->documentationUrl)->toStartWith('https://')
            ->and($setup->secretCredentialKeys())->not->toBeEmpty($setup->name.' declares no secret');

        foreach ($setup->credentialKeys() as $key) {
            if (preg_match('/secret|token|password|api_key/', $key) === 1) {
                expect($setup->secretCredentialKeys())->toContain($key);
            }
        }

        expect(app(DirectoryConnectors::class)->for($setup->provider)->supportsIncremental())->toBe($setup->incremental);
    }
});

it('declares exactly the credentials each connector demands', function (DirectoryProvider $provider, array $complete): void {
    $connector = app(DirectoryConnectors::class)->for($provider);
    $setup = HrisCatalog::for($provider);

    expect($connector)->toBeInstanceOf(HrisProvider::class)
        ->and(array_diff(array_keys($complete), $setup?->credentialKeys() ?? []))->toBe([]);

    /** @var HrisProvider $connector */
    expect($connector->verify(HrisCatalog::credentialsFrom($provider, $complete)))->toBeTrue();

    foreach (array_keys($complete) as $omitted) {
        $short = $complete;
        unset($short[$omitted]);

        expect(fn () => iterator_to_array($connector->fetchEmployees($short, new HrisSyncOptions)))
            ->toThrow(DirectoryConnectionFailed::class, 'Missing credential: '.$omitted);
    }
})->with([
    'workday with an integration user' => [DirectoryProvider::Workday, ['report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU/Workers', 'username' => 'ISU@acme', 'password' => 'pw']],
    'workday with an API client' => [DirectoryProvider::Workday, ['report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU/Workers', 'client_id' => 'c', 'client_secret' => 's', 'refresh_token' => 'r']],
    'bamboohr' => [DirectoryProvider::BambooHr, ['subdomain' => 'acme', 'api_key' => 'k']],
    'rippling' => [DirectoryProvider::Rippling, ['api_token' => 't']],
    'hibob' => [DirectoryProvider::HiBob, ['service_user_id' => 'SERVICE-1', 'service_user_token' => 't']],
    'personio' => [DirectoryProvider::Personio, ['client_id' => 'c', 'client_secret' => 's']],
]);

it('normalises and refuses credentials before anything is stored', function (): void {
    expect(HrisCatalog::credentialsFrom(DirectoryProvider::BambooHr, ['subdomain' => ' https://Acme.bamboohr.com/home ', 'api_key' => ' k ', 'stray' => 'x']))
        ->toBe(['subdomain' => 'acme', 'api_key' => 'k'])
        ->and(HrisCatalog::credentialsFrom(DirectoryProvider::Workday, [
            'report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU/Workers?format=csv&Effective_as_of=2026-01-01',
            'username' => 'ISU@acme', 'password' => 'pw', 'client_id' => 'half an oauth client',
        ]))->toBe([
            'report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU/Workers?format=json&Effective_as_of=2026-01-01',
            'username' => 'ISU@acme',
            'password' => 'pw',
        ]);

    $refusals = [
        [DirectoryProvider::BambooHr, ['subdomain' => 'acme'], ['api_key']],
        [DirectoryProvider::BambooHr, ['subdomain' => 'evil.example/x?', 'api_key' => 'k'], ['subdomain']],
        [DirectoryProvider::Workday, ['report_url' => 'https://wd5-services1.myworkday.com/ccx/service/customreport2/acme/ISU/Workers', 'username' => 'u'], ['password']],
        [DirectoryProvider::Workday, ['report_url' => 'https://evil.example/ccx/service/customreport2/a/b/c', 'username' => 'u', 'password' => 'p'], ['report_url']],
        [DirectoryProvider::Personio, ['client_id' => 'c'], ['client_secret']],
        [DirectoryProvider::Scim, [], ['provider']],
    ];

    foreach ($refusals as [$provider, $given, $keys]) {
        try {
            HrisCatalog::credentialsFrom($provider, $given);
            $this->fail($provider->value.' accepted '.json_encode($given));
        } catch (IncompleteHrisCredentials $e) {
            expect($e->keys)->toBe($keys);
        }
    }
});
