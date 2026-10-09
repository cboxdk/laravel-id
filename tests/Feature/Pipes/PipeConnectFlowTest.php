<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\Pipes\Exceptions\PipeConnectFailed;
use Cbox\Id\Pipes\Exceptions\PipeNotFound;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\PipeOAuthClient;
use Cbox\Id\Pipes\PipeProviderCatalog;
use Cbox\Id\Pipes\Support\PipeSecrets;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.pipes.verify_url' => false]);
});

/**
 * Every provider's real token-response shape, and what the connection must make of it.
 *
 * @return array<string, array{0: string, 1: array<string, mixed>, 2: array<string, mixed>, 3: array<string, mixed>}>
 */
function pipeProviderFlows(): array
{
    return [
        'GitHub (non-expiring OAuth App token)' => ['github',
            ['access_token' => 'gho_ACCESS', 'token_type' => 'bearer', 'scope' => 'read:user,repo'],
            ['https://api.github.com/user' => ['login' => 'octocat']],
            ['access' => 'gho_ACCESS', 'refresh' => null, 'expires_in' => null, 'label' => 'octocat', 'scopes' => ['read:user', 'repo'], 'metadata' => []]],
        'Google' => ['google',
            ['access_token' => 'ya29.ACCESS', 'expires_in' => 3599, 'refresh_token' => '1//REFRESH', 'scope' => 'openid email profile', 'token_type' => 'Bearer', 'id_token' => 'header.payload.sig'],
            ['https://openidconnect.googleapis.com/v1/userinfo' => ['email' => 'dana@corp.test']],
            ['access' => 'ya29.ACCESS', 'refresh' => '1//REFRESH', 'expires_in' => 3599, 'label' => 'dana@corp.test', 'scopes' => ['openid', 'email', 'profile'], 'metadata' => []]],
        'Microsoft 365' => ['microsoft',
            ['access_token' => 'eyJ.ACCESS', 'expires_in' => 3600, 'refresh_token' => 'M.REFRESH', 'scope' => 'User.Read offline_access', 'token_type' => 'Bearer'],
            ['https://graph.microsoft.com/v1.0/me' => ['userPrincipalName' => 'dana@contoso.com']],
            ['access' => 'eyJ.ACCESS', 'refresh' => 'M.REFRESH', 'expires_in' => 3600, 'label' => 'dana@contoso.com', 'scopes' => ['User.Read', 'offline_access'], 'metadata' => []]],
        'Slack (the user token, not the bot token)' => ['slack',
            ['ok' => true, 'access_token' => 'xoxb-BOT', 'team' => ['id' => 'T1', 'name' => 'Acme'], 'authed_user' => ['id' => 'U1', 'scope' => 'users:read', 'access_token' => 'xoxp-ACCESS', 'token_type' => 'user', 'refresh_token' => 'xoxe-REFRESH', 'expires_in' => 43200]],
            [],
            ['access' => 'xoxp-ACCESS', 'refresh' => 'xoxe-REFRESH', 'expires_in' => 43200, 'label' => 'Acme', 'scopes' => ['users:read'], 'metadata' => ['team.id' => 'T1', 'team.name' => 'Acme', 'authed_user.id' => 'U1']]],
        'Salesforce (no expires_in; instance_url is essential)' => ['salesforce',
            ['access_token' => '00D!ACCESS', 'refresh_token' => '5Aep-REFRESH', 'instance_url' => 'https://acme.my.salesforce.com', 'id' => 'https://login.salesforce.com/id/00D/005', 'token_type' => 'Bearer', 'scope' => 'api refresh_token'],
            [],
            ['access' => '00D!ACCESS', 'refresh' => '5Aep-REFRESH', 'expires_in' => 7200, 'label' => null, 'scopes' => ['api', 'refresh_token'], 'metadata' => ['instance_url' => 'https://acme.my.salesforce.com', 'id' => 'https://login.salesforce.com/id/00D/005']]],
        'HubSpot' => ['hubspot',
            ['access_token' => 'CJ-ACCESS', 'refresh_token' => 'na1-REFRESH', 'expires_in' => 1800, 'token_type' => 'bearer'],
            [],
            ['access' => 'CJ-ACCESS', 'refresh' => 'na1-REFRESH', 'expires_in' => 1800, 'label' => null, 'scopes' => ['oauth', 'crm.objects.contacts.read'], 'metadata' => []]],
        'Linear' => ['linear',
            ['access_token' => 'lin_oauth_ACCESS', 'token_type' => 'Bearer', 'expires_in' => 86399, 'scope' => ['read'], 'refresh_token' => 'lin_refresh_REFRESH'],
            [],
            ['access' => 'lin_oauth_ACCESS', 'refresh' => 'lin_refresh_REFRESH', 'expires_in' => 86399, 'label' => null, 'scopes' => ['read'], 'metadata' => []]],
        'Notion (JSON body, Basic auth, no scopes)' => ['notion',
            ['access_token' => 'secret_ACCESS', 'refresh_token' => 'nr_REFRESH', 'token_type' => 'bearer', 'bot_id' => 'b1', 'workspace_name' => 'Acme HQ', 'workspace_id' => 'w1'],
            [],
            ['access' => 'secret_ACCESS', 'refresh' => 'nr_REFRESH', 'expires_in' => null, 'label' => 'Acme HQ', 'scopes' => [], 'metadata' => ['workspace_id' => 'w1', 'workspace_name' => 'Acme HQ', 'bot_id' => 'b1']]],
    ];
}

it('connects an account end to end', function (string $provider, array $tokenResponse, array $accountResponses, array $expect): void {
    $pipe = app(Pipes::class)->configure($provider, 'the-client-id', 'the-client-secret');
    $entry = PipeProviderCatalog::find($provider);
    $tokenUrl = $entry?->endpoint($entry->tokenEndpoint, $pipe->parameterValues());

    $fakes = [$tokenUrl => Http::response($tokenResponse)];
    foreach ($accountResponses as $url => $body) {
        $fakes[$url] = Http::response($body);
    }
    Http::fake($fakes);

    $connections = app(PipeConnections::class);
    $authorization = $connections->start($provider, 'user_1', 'https://id.test/account/pipes/'.$provider.'/callback');

    // The authorization request: PKCE S256 over the verifier only the session holds, the
    // state, the pipe's scopes in the provider's own parameter, and its fixed extras.
    parse_str((string) parse_url($authorization->url, PHP_URL_QUERY), $query);
    expect($authorization->url)->toStartWith($entry?->endpoint($entry->authorizationEndpoint, $pipe->parameterValues()).'?')
        ->and($query['client_id'])->toBe('the-client-id')
        ->and($query['state'])->toBe($authorization->state->state)
        ->and($query['code_challenge_method'])->toBe('S256')
        ->and($query['code_challenge'])->toBe(PipeOAuthClient::codeChallenge($authorization->state->codeVerifier))
        ->and($query)->not->toHaveKey('code_verifier');

    if ($entry?->defaultScopes !== []) {
        expect($query[$entry?->scopeParameter])->toBe($entry?->scopeString($entry->defaultScopes));
    }

    foreach ($entry?->authorizeParameters ?? [] as $key => $value) {
        expect($query[$key])->toBe($value);
    }

    $connection = $connections->complete($authorization->state, $authorization->state->state, 'the-code');

    // The token request carried the code, the redirect and the PKCE verifier, and
    // authenticated the client exactly one way.
    Http::assertSent(function (Request $request) use ($tokenUrl, $authorization, $entry): bool {
        if ($request->url() !== $tokenUrl) {
            return false;
        }

        $data = $request->data();
        $basic = $request->hasHeader('Authorization');

        return $data['code'] === 'the-code'
            && $data['grant_type'] === 'authorization_code'
            && $data['code_verifier'] === $authorization->state->codeVerifier
            && $data['redirect_uri'] === $authorization->state->redirectUri
            && ($entry?->tokenRequestFormat->value === 'json' ? $request->isJson() : $request->isForm())
            && ($basic xor isset($data['client_secret']))
            && collect($entry->requestHeaders ?? [])->every(fn (string $value, string $name): bool => $request->header($name) === [$value]);
    });

    expect($connection->status)->toBe(PipeConnectionStatus::Active)
        ->and($connection->user_id)->toBe('user_1')
        ->and($connection->provider)->toBe($provider)
        ->and($connection->scopes)->toBe($expect['scopes'])
        ->and($connection->metadata)->toBe($expect['metadata'])
        ->and($connection->account_label)->toBe($expect['label']);

    if ($expect['expires_in'] === null) {
        expect($connection->access_expires_at)->toBeNull();
    } else {
        expect(abs($connection->access_expires_at?->diffInSeconds(now()->addSeconds($expect['expires_in'])) ?? 999))->toBeLessThan(5);
    }

    // The tokens are user-owned vault secrets, sealed — and readable only through the
    // vault by the broker.
    $access = VaultSecret::query()->whereKey($connection->access_secret_id)->firstOrFail();
    expect($access->owner_type)->toBe('user')
        ->and($access->owner_id)->toBe('user_1')
        ->and($access->secret_encrypted)->not->toContain($expect['access'])
        ->and(app(PipeSecrets::class)->open($connection->access_secret_id, 'user_1', 'test'))->toBe($expect['access']);

    if ($expect['refresh'] === null) {
        expect($connection->refresh_secret_id)->toBeNull();
    } else {
        expect(app(PipeSecrets::class)->open((string) $connection->refresh_secret_id, 'user_1', 'test'))->toBe($expect['refresh']);
    }
})->with(pipeProviderFlows());

it('refuses a callback whose state does not match, without calling the provider', function (): void {
    Http::fake();
    $this->configurePipe('github');
    $authorization = app(PipeConnections::class)->start('github', 'user_1', 'https://id.test/cb');

    expect(fn () => app(PipeConnections::class)->complete($authorization->state, 'forged-state', 'code'))
        ->toThrow(fn (PipeConnectFailed $e) => expect($e->reason)->toBe('state_mismatch'));

    Http::assertNothingSent();
    expect(PipeConnection::query()->count())->toBe(0);
});

it('refuses to start for a provider the environment has not configured, or has disabled', function (): void {
    expect(fn () => app(PipeConnections::class)->start('github', 'user_1', 'https://id.test/cb'))->toThrow(PipeNotFound::class);

    $pipe = $this->configurePipe('github');
    app(Pipes::class)->update($pipe->id, enabled: false);

    expect(fn () => app(PipeConnections::class)->start('github', 'user_1', 'https://id.test/cb'))->toThrow(PipeNotFound::class);
});

it('fails closed when the pipe was disabled while the person was at the provider', function (): void {
    Http::fake();
    $pipe = $this->configurePipe('github');
    $authorization = app(PipeConnections::class)->start('github', 'user_1', 'https://id.test/cb');
    app(Pipes::class)->update($pipe->id, enabled: false);

    expect(fn () => app(PipeConnections::class)->complete($authorization->state, $authorization->state->state, 'code'))
        ->toThrow(fn (PipeConnectFailed $e) => expect($e->reason)->toBe('pipe_unavailable'));

    Http::assertNothingSent();
});

it('stores nothing when the provider refuses the code — and keeps the error body out of the exception', function (): void {
    Http::fake(['github.com/login/oauth/access_token' => Http::response([
        'error' => 'bad_verification_code',
        'error_description' => 'The code passed is incorrect or expired. echo: gho_SHOULD_NOT_LEAK',
    ])]);
    $this->fakeAudit();
    $this->configurePipe('github');
    $authorization = app(PipeConnections::class)->start('github', 'user_1', 'https://id.test/cb');

    try {
        app(PipeConnections::class)->complete($authorization->state, $authorization->state->state, 'code');
        $this->fail('expected the connect to fail');
    } catch (PipeConnectFailed $e) {
        expect($e->reason)->toBe('exchange_failed')
            ->and($e->getMessage())->not->toContain('gho_SHOULD_NOT_LEAK');
    }

    expect(PipeConnection::query()->count())->toBe(0)
        ->and(VaultSecret::query()->count())->toBe(0);

    $audit = app(AuditLog::class);
    $audit->assertRecorded('pipe.connection.failed', fn ($event): bool => $event->context['reason'] === 'bad_verification_code');
    expect(json_encode($audit->recorded))->not->toContain('gho_SHOULD_NOT_LEAK');
});

it('reconnecting replaces the tokens in place and brings a connection back from needs_reauth', function (): void {
    $this->configurePipe('hubspot');
    $first = $this->connectPipeAccount('hubspot', 'user_1', ['access_token' => 'old-access', 'refresh_token' => 'old-refresh', 'expires_in' => 1800]);
    $first->forceFill(['status' => PipeConnectionStatus::NeedsReauth, 'reauth_reason' => 'invalid_grant'])->save();

    $second = $this->connectPipeAccount('hubspot', 'user_1', ['access_token' => 'new-access', 'refresh_token' => 'new-refresh', 'expires_in' => 1800]);

    expect($second->id)->toBe($first->id)
        ->and($second->status)->toBe(PipeConnectionStatus::Active)
        ->and($second->reauth_reason)->toBeNull()
        ->and($second->access_secret_id)->toBe($first->access_secret_id)
        ->and(app(PipeSecrets::class)->open($second->access_secret_id, 'user_1', 't'))->toBe('new-access')
        ->and(app(PipeSecrets::class)->open((string) $second->refresh_secret_id, 'user_1', 't'))->toBe('new-refresh')
        ->and(PipeConnection::query()->count())->toBe(1);
});

it('binds the connection to the person who started the flow, whoever completes it', function (): void {
    $this->configurePipe('github');
    Http::fake(['github.com/login/oauth/access_token' => Http::response(['access_token' => 'gho_x']), 'api.github.com/user' => Http::response([])]);
    $authorization = app(PipeConnections::class)->start('github', 'user_alice', 'https://id.test/cb');

    $connection = app(PipeConnections::class)->complete($authorization->state, $authorization->state->state, 'code');

    expect($connection->user_id)->toBe('user_alice');
});
