<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\SignInProviders;
use Cbox\Id\Federation\Enums\ConnectionStatus;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\Models\Connection;
use Cbox\Id\Federation\OAuth2Client;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/*
 * SOCIAL SIGN-IN, OWNED BY THE ENVIRONMENT AND INHERITED BY ITS ORGANIZATIONS.
 *
 * "Turn on Google for my app" is one set of credentials offered on every sign-in page. An
 * organization may bring its own (which replaces the environment's), or stop offering the
 * environment's on its page. See SignInProviders for the precedence these hold.
 */
function socialProvider(?string $organizationId, string $provider, ConnectionStatus $status = ConnectionStatus::Active): Connection
{
    $connection = app(SignInProviders::class)->create(
        $organizationId,
        $provider,
        ConnectionType::OAuth2,
        ucfirst($provider),
        ['provider' => $provider, 'client_id' => 'id-'.$provider, 'client_secret' => 'secret'],
    );

    if ($status === ConnectionStatus::Active) {
        app(Connections::class)->activate($organizationId, $connection->id);
    } elseif ($status === ConnectionStatus::Inactive) {
        $connection->forceFill(['status' => ConnectionStatus::Inactive])->save();
    }

    return $connection->refresh();
}

/** @return array<string, string|null> provider key => owning organization */
function offered(?string $organizationId): array
{
    $offered = [];

    foreach (app(SignInProviders::class)->offeredTo($organizationId) as $connection) {
        $offered[(string) $connection->provider] = $connection->organization_id;
    }

    return $offered;
}

it('offers the environment\'s providers on every organization\'s page and on the plain one', function (): void {
    socialProvider(null, 'github');
    socialProvider(null, 'discord');

    expect(offered(null))->toBe(['discord' => null, 'github' => null])
        ->and(offered('org-acme'))->toBe(['discord' => null, 'github' => null]);
});

it('lets an organization\'s own provider replace the environment\'s for that key', function (): void {
    socialProvider(null, 'github');
    socialProvider(null, 'discord');
    socialProvider('org-acme', 'github');

    expect(offered('org-acme'))->toBe(['discord' => null, 'github' => 'org-acme'])
        // Nobody else is affected, and the plain page still shows the environment's.
        ->and(offered('org-other'))->toBe(['discord' => null, 'github' => null])
        ->and(offered(null))->toBe(['discord' => null, 'github' => null]);
});

it('does not fall back to the environment\'s credentials when the organization turned its own off', function (): void {
    socialProvider(null, 'github');
    socialProvider('org-acme', 'github', ConnectionStatus::Inactive);

    expect(offered('org-acme'))->toBe([]);
});

it('lets a half-saved draft replace nothing', function (): void {
    socialProvider(null, 'github');
    socialProvider('org-acme', 'github', ConnectionStatus::Draft);

    expect(offered('org-acme'))->toBe(['github' => null]);
});

it('lets an organization stop and resume inheriting one provider', function (): void {
    socialProvider(null, 'github');
    socialProvider(null, 'discord');
    $providers = app(SignInProviders::class);

    expect($providers->stopInheriting('org-acme', 'github'))->toBeTrue()
        ->and($providers->stopInheriting('org-acme', 'github'))->toBeFalse()
        ->and(offered('org-acme'))->toBe(['discord' => null])
        ->and(offered('org-other'))->toBe(['discord' => null, 'github' => null])
        ->and($providers->notInheritedBy('org-acme'))->toBe(['github'])
        ->and($providers->optOuts())->toBe(['org-acme' => ['github']]);

    // Its own GitHub still shows: stopping inheritance is about the environment's.
    socialProvider('org-acme', 'github');
    expect(offered('org-acme'))->toBe(['discord' => null, 'github' => 'org-acme']);

    expect($providers->resumeInheriting('org-acme', 'github'))->toBeTrue()
        ->and($providers->resumeInheriting('org-acme', 'github'))->toBeFalse()
        ->and($providers->notInheritedBy('org-acme'))->toBe([]);
});

it('offers nothing the environment turned off', function (): void {
    socialProvider(null, 'github', ConnectionStatus::Inactive);

    expect(offered('org-acme'))->toBe([])
        ->and(app(SignInProviders::class)->environmentProviders())->toHaveCount(1);
});

it('keeps one environment\'s providers and opt-outs out of another\'s', function (): void {
    $environments = app(EnvironmentContext::class);

    $environments->runAs(GenericEnvironment::of('env_a'), function (): void {
        socialProvider(null, 'github');
        app(SignInProviders::class)->stopInheriting('org-shared-id', 'discord');
    });

    $inB = $environments->runAs(GenericEnvironment::of('env_b'), fn (): array => [
        offered('org-shared-id'),
        app(SignInProviders::class)->notInheritedBy('org-shared-id'),
        app(SignInProviders::class)->environmentProviders(),
    ]);

    expect($inB)->toBe([[], [], []]);
});

it('creates a provider under a reserved id, so its redirect URI can be shown before it exists', function (): void {
    $id = strtolower((string) Str::ulid());

    $connection = app(SignInProviders::class)->create(null, 'github', ConnectionType::OAuth2, 'GitHub', [
        'provider' => 'github', 'client_id' => 'abc', 'client_secret' => 'shh',
    ], $id);

    expect($connection->id)->toBe($id)
        ->and($connection->status)->toBe(ConnectionStatus::Draft)
        ->and(app(Connections::class)->oauth2Config($connection->refresh())->clientSecret)->toBe('shh');
});

it('refuses a reserved id that is not a ULID or is already taken — in any environment', function (): void {
    $taken = app(EnvironmentContext::class)->runAs(GenericEnvironment::of('env_elsewhere'), fn (): string => socialProvider(null, 'github')->id);

    $create = fn (string $id) => app(SignInProviders::class)->create(null, 'discord', ConnectionType::OAuth2, 'Discord', [
        'provider' => 'discord', 'client_id' => 'abc', 'client_secret' => 'shh',
    ], $id);

    expect(fn () => $create('not-a-ulid'))->toThrow(InvalidAssertion::class)
        ->and(fn () => $create($taken))->toThrow(InvalidAssertion::class);
});

it('requests an OAuth 2.0 provider\'s extra scopes on top of the catalogue\'s, never instead of them', function (): void {
    $template = ProviderCatalog::find('github');
    expect($template)->not->toBeNull();

    $config = OAuth2ConnectionConfig::fromArray([
        'provider' => 'github', 'client_id' => 'abc', 'client_secret' => 'shh',
        'scopes' => ['read:org', ' ', 'read:org', 7],
    ]);

    parse_str((string) parse_url(app(OAuth2Client::class)->authorizeUrl($template, $config, 'https://id.test/cb', 'state'), PHP_URL_QUERY), $query);

    expect($config->scopes)->toBe(['read:org'])
        ->and(explode(' ', (string) $query['scope']))->toBe([...$template->scopes, 'read:org']);
});
