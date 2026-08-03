<?php

declare(strict_types=1);

use Cbox\Id\Directory\Connectors\GoogleWorkspaceConnector;
use Cbox\Id\Directory\Connectors\MicrosoftEntraConnector;
use Cbox\Id\Directory\Contracts\DirectoryConnector;
use Cbox\Id\Directory\Enums\DirectoryProvider;
use Cbox\Id\Directory\Exceptions\DirectoryConnectionFailed;
use Cbox\Id\Federation\Enums\FederationProtocol;
use Cbox\Id\Federation\Enums\ProviderCapability;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\ProviderCapabilities;
use Cbox\Id\Federation\ValueObjects\ProviderProfileMap;
use Cbox\Id\Federation\ValueObjects\ProviderTemplate;
use Illuminate\Support\Facades\Http;

/**
 * One catalogue, several capabilities.
 *
 * The failure these guard against is not a crash. It is an administrator on the directory
 * screen being shown a provider with no guide, or a form asking for fields the connector
 * will not read — both of which look like working software until the first sync at 3am
 * provisions nobody.
 */
function capabilityTestRsaKey(): string
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($key, $pem);

    return $pem;
}

it('holds a capability set, not a list of strings', function (): void {
    $set = new ProviderCapabilities(ProviderCapability::Login, ProviderCapability::Directory, ProviderCapability::Login);

    // A set: asking the same question twice cannot give two answers.
    expect($set)->toHaveCount(2)
        ->and($set->has(ProviderCapability::Login))->toBeTrue()
        ->and($set->has(ProviderCapability::Directory))->toBeTrue()
        ->and($set->values())->toBe(['login', 'directory'])
        ->and(iterator_to_array($set))->toBe([ProviderCapability::Login, ProviderCapability::Directory])
        ->and((new ProviderCapabilities)->isEmpty())->toBeTrue();
});

it('gives every catalogue entry at least one thing it can do', function (): void {
    foreach (ProviderCatalog::all() as $template) {
        expect($template->capabilities()->isEmpty())
            ->toBeFalse($template->key.' is in the catalogue but can be used for nothing');
    }
});

/**
 * The capability is read off the entry's contents, never declared beside them. A template
 * that claimed `directory` with no setup on it would put a provider in the console's list
 * that the console cannot then show one field for.
 */
it('derives the directory capability from the setup that proves it', function (): void {
    $google = ProviderCatalog::find('google');
    $slack = ProviderCatalog::find('slack');

    expect($google?->supports(ProviderCapability::Directory))->toBeTrue()
        ->and($google?->directory)->not->toBeNull()
        ->and($slack?->supports(ProviderCapability::Directory))->toBeFalse()
        ->and($slack?->directory)->toBeNull();

    foreach (ProviderCatalog::all() as $template) {
        expect($template->supports(ProviderCapability::Directory))
            ->toBe($template->directory !== null, $template->key.' claims a capability its contents do not carry');
    }
});

it('offers for sign-in only what a person could actually be sent to', function (): void {
    // An entry with nowhere to send anybody is not a sign-in provider however OIDC-shaped
    // it looks. Asserted on a hand-built template because the shipped catalogue has none —
    // which is the point: the rule has to hold for the entry somebody adds next.
    $nowhere = new ProviderTemplate(
        key: 'nowhere',
        name: 'Nowhere',
        protocol: FederationProtocol::Oidc,
        scopes: ['openid'],
        profile: new ProviderProfileMap(subject: 'sub', email: 'email', name: 'name'),
    );

    expect($nowhere->supportsLogin())->toBeFalse()
        ->and($nowhere->capabilities()->isEmpty())->toBeTrue()
        ->and($nowhere->supports(ProviderCapability::Login))->toBeFalse();

    foreach (ProviderCatalog::withCapability(ProviderCapability::Login) as $template) {
        $reachable = $template->isOidc()
            ? $template->issuerTemplate !== null
            : $template->authorizationEndpoint !== null && $template->tokenEndpoint !== null;

        expect($reachable)->toBeTrue($template->key.' is offered for sign-in with nowhere to send anybody');
    }

    expect(array_map(
        static fn (ProviderTemplate $t): string => $t->key,
        ProviderCatalog::withCapability(ProviderCapability::Directory),
    ))->toBe(['google', 'microsoft']);
});

/**
 * The point of the merge. A directory setup with no steps is the empty screen this whole
 * change exists to remove, and it is worth remembering that the directory steps are NOT
 * the login steps: connecting Google for sign-in is an OAuth client, connecting it as a
 * directory is a service account with domain-wide delegation, and an administrator handed
 * the wrong one reaches the end before finding out.
 */
it('carries a directory guide that is not the login guide', function (): void {
    foreach (ProviderCatalog::withCapability(ProviderCapability::Directory) as $template) {
        $directory = $template->directory;

        expect($directory)->not->toBeNull()
            ->and($directory->setupSteps)->not->toBeEmpty($template->key.' has a directory with no setup steps')
            ->and($directory->documentationUrl)->toStartWith('https://')
            ->and($directory->credentials)->not->toBeEmpty($template->key.' asks for no directory credentials')
            ->and($directory->setupSteps)->not->toBe($template->setupSteps, $template->key.' reuses its login steps for a directory, which they do not describe');
    }
});

/**
 * Deny-by-default, from the other side: a connector the product ships with no entry in
 * the catalogue is exactly the state that produced the empty directory screen, so adding
 * one without a guide fails the build rather than shipping.
 */
it('has an entry for every pull provider the product ships a connector for', function (): void {
    $connectors = [new GoogleWorkspaceConnector, new MicrosoftEntraConnector];

    foreach ($connectors as $connector) {
        expect(ProviderCatalog::forDirectory($connector->provider()))
            ->not->toBeNull($connector->provider()->value.' has a connector but no catalogue entry, so its setup screen has nothing to show');
    }

    // Round-trips: the entry found for a provider is the one that names it.
    foreach (DirectoryProvider::cases() as $provider) {
        $template = ProviderCatalog::forDirectory($provider);

        if ($template !== null) {
            expect($template->directory?->provider)->toBe($provider);
        }
    }
});

/**
 * SCIM is not a provider in the sense the catalogue means, and this pins that decision so
 * it is reversed on purpose rather than by somebody adding an entry for symmetry.
 *
 * Everything in the catalogue is a service we go to, holding a credential the customer
 * made for us. SCIM is the customer's own identity provider coming to US, against an
 * endpoint and a token we mint — no issuer, no vendor, no third-party documentation,
 * because the far end is whatever they happen to run.
 */
it('keeps SCIM out of the catalogue, because it is a protocol and not a provider', function (): void {
    expect(ProviderCatalog::forDirectory(DirectoryProvider::Scim))->toBeNull()
        ->and(DirectoryProvider::Scim->isPull())->toBeFalse()
        // And the enum still answers for it, because a stored row must render with no
        // catalogue entry behind it.
        ->and(DirectoryProvider::Scim->label())->not->toBe('');
});

/**
 * The catalogue's credential list and the connector's demands are one contract.
 *
 * A form built from a stale list collects fields nobody reads and misses one nobody
 * asked for — and the connection is stored anyway, because a credential map is just an
 * array until something uses it. So the declared credentials are driven through the REAL
 * connector: the full set must satisfy it, and dropping any single one must not.
 */
it('declares exactly the credentials each connector demands', function (DirectoryConnector $connector, string $key, string $value): void {
    Http::fake([
        'oauth2.googleapis.com/*' => Http::response(['access_token' => 'ya29.token']),
        'admin.googleapis.com/*' => Http::response(['users' => []]),
        'login.microsoftonline.com/*' => Http::response(['access_token' => 'graph.token']),
        'graph.microsoft.com/*' => Http::response(['value' => []]),
    ]);

    $template = ProviderCatalog::forDirectory($connector->provider());
    $declared = $template?->directory?->credentialKeys() ?? [];

    expect($declared)->not->toBeEmpty();

    /** @var array<string, string> $credentials */
    $credentials = [];

    foreach ($declared as $declaredKey) {
        $credentials[$declaredKey] = $declaredKey === $key ? $value : 'declared-'.$declaredKey;
    }

    // Nothing missing: the declared set is enough for the connector to reach the provider.
    expect($connector->verify($credentials))->toBeTrue(
        $connector->provider()->value.' refuses the credentials the catalogue tells an administrator to supply',
    );

    // Nothing surplus: every declared credential is load-bearing. `verify()` swallows the
    // refusal into false, so the connector is asked directly for the one that reports why.
    foreach ($declared as $omitted) {
        $short = $credentials;
        unset($short[$omitted]);

        expect(fn () => iterator_to_array($connector->fetchUsers($short)))
            ->toThrow(DirectoryConnectionFailed::class, 'Missing credential: '.$omitted, $omitted.' is declared but the connector never reads it');
    }
})->with(fn (): array => [
    'google workspace' => [new GoogleWorkspaceConnector, 'private_key', capabilityTestRsaKey()],
    'microsoft entra' => [new MicrosoftEntraConnector, 'tenant_id', '72f988bf-86f1-41af-91ab-2d7cd011db47'],
]);
