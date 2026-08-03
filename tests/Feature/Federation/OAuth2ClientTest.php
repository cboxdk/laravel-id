<?php

declare(strict_types=1);

use Cbox\Id\Federation\Exceptions\InvalidAssertion;
use Cbox\Id\Federation\OAuth2Client;
use Cbox\Id\Federation\ProviderCatalog;
use Cbox\Id\Federation\ValueObjects\OAuth2ConnectionConfig;
use Illuminate\Support\Facades\Http;

function githubConfig(): OAuth2ConnectionConfig
{
    return new OAuth2ConnectionConfig('github', 'client-id', 'client-secret');
}

/**
 * GitHub returns `email: null` for anyone who has not made their address public, which
 * is the default — so without the second call a majority of GitHub sign-ins arrive with
 * no address at all.
 */
it('falls back to the primary address when the profile carries none', function (): void {
    Http::fake([
        'github.com/login/oauth/access_token' => Http::response(['access_token' => 'gho_test']),
        'api.github.com/user' => Http::response(['id' => 4711, 'login' => 'dana', 'name' => 'Dana', 'email' => null]),
        'api.github.com/user/emails' => Http::response([
            ['email' => 'old@personal.test', 'primary' => false, 'verified' => true],
            ['email' => 'dana@corp.test', 'primary' => true, 'verified' => true],
        ]),
    ]);

    $principal = app(OAuth2Client::class)->principal(
        ProviderCatalog::find('github'),
        githubConfig(),
        'the-code',
        'https://id.test/callback',
    );

    // The PRIMARY, not the first in the list: the order is not guaranteed, and taking
    // whichever came back first attaches the account to an address the person may have
    // added years ago and forgotten.
    expect($principal->email)->toBe('dana@corp.test')
        // The immutable numeric id, as a string — a subject whose type changes between
        // providers is a subject that fails to match the link written last time.
        ->and($principal->subject)->toBe('4711')
        ->and($principal->provider)->toBe('oauth2:github')
        ->and($principal->name)->toBe('Dana');
});

it('does not ask for addresses when the profile already carried one', function (): void {
    Http::fake([
        'github.com/login/oauth/access_token' => Http::response(['access_token' => 'gho_test']),
        'api.github.com/user' => Http::response(['id' => 12, 'name' => 'Pat', 'email' => 'pat@corp.test']),
        'api.github.com/user/emails' => Http::response([['email' => 'other@corp.test', 'primary' => true]]),
    ]);

    $principal = app(OAuth2Client::class)->principal(
        ProviderCatalog::find('github'),
        githubConfig(),
        'the-code',
        'https://id.test/callback',
    );

    expect($principal->email)->toBe('pat@corp.test');

    Http::assertNotSent(fn ($request): bool => str_contains($request->url(), '/user/emails'));
});

/**
 * These providers answer 200 with an error body rather than a 4xx, so a successful
 * response proves nothing on its own.
 */
it('refuses a token response that carried no access token', function (): void {
    Http::fake([
        'github.com/login/oauth/access_token' => Http::response(['error' => 'bad_verification_code']),
    ]);

    app(OAuth2Client::class)->principal(
        ProviderCatalog::find('github'),
        githubConfig(),
        'the-code',
        'https://id.test/callback',
    );
})->throws(InvalidAssertion::class, 'token response contained no access_token');

it('refuses a profile with no immutable identifier', function (): void {
    Http::fake([
        'github.com/login/oauth/access_token' => Http::response(['access_token' => 'gho_test']),
        'api.github.com/user' => Http::response(['login' => 'dana', 'email' => 'dana@corp.test']),
    ]);

    app(OAuth2Client::class)->principal(
        ProviderCatalog::find('github'),
        githubConfig(),
        'the-code',
        'https://id.test/callback',
    );
})->throws(InvalidAssertion::class);

/**
 * Driving an OIDC provider through this path would exchange a code and then never verify
 * an id_token — authentication with the signature step quietly missing.
 */
it('refuses a configuration naming an OIDC provider', function (): void {
    OAuth2ConnectionConfig::fromArray([
        'provider' => 'google',
        'client_id' => 'x',
        'client_secret' => 'y',
    ]);
})->throws(InvalidAssertion::class, 'connection names no OAuth 2.0 provider: google');

it('sends the browser to the provider with our client id and an opaque state', function (): void {
    $url = app(OAuth2Client::class)->authorizeUrl(
        ProviderCatalog::find('discord'),
        new OAuth2ConnectionConfig('discord', 'discord-client', 'secret'),
        'https://id.test/callback',
        'state-123',
    );

    expect($url)->toStartWith('https://discord.com/oauth2/authorize?')
        ->toContain('client_id=discord-client')
        ->toContain('state=state-123')
        ->toContain('response_type=code')
        // The scopes come from the catalogue, not from the caller.
        ->toContain('identify')
        ->toContain('email');
});
