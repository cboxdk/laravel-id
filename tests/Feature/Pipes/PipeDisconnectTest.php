<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\SubjectPseudonym;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

it('revokes at the provider the way each provider wants it', function (string $provider, array $tokens, Closure $expectedCall): void {
    $this->configurePipe($provider, clientId: 'the-client', clientSecret: 'the-secret');
    $connection = $this->connectPipeAccount($provider, 'user_1', $tokens);
    Http::fake(['*' => Http::response(['ok' => true])]);

    $revoked = app(PipeConnections::class)->disconnect($connection->id, 'user_1');

    expect($revoked)->toBeTrue();
    Http::assertSentCount(1);
    Http::assertSent($expectedCall);
})->with([
    'GitHub: DELETE the grant, Basic client auth, token in the body' => ['github', ['access_token' => 'gho_A'],
        fn (Request $r): bool => $r->method() === 'DELETE'
            && $r->url() === 'https://api.github.com/applications/the-client/grant'
            && $r->header('Authorization')[0] === 'Basic '.base64_encode('the-client:the-secret')
            && $r['access_token'] === 'gho_A'],
    'Google: RFC 7009 with the refresh token' => ['google', ['access_token' => 'ya29.A', 'refresh_token' => '1//R', 'expires_in' => 3600],
        fn (Request $r): bool => $r->method() === 'POST' && $r->url() === 'https://oauth2.googleapis.com/revoke' && $r['token'] === '1//R' && $r['token_type_hint'] === 'refresh_token'],
    'Salesforce: RFC 7009 on the configured domain' => ['salesforce', ['access_token' => '00D!A', 'refresh_token' => '5Aep'],
        fn (Request $r): bool => $r->url() === 'https://login.salesforce.com/services/oauth2/revoke' && $r['token'] === '5Aep'],
    'Slack: auth.revoke with the user token' => ['slack', ['ok' => true, 'authed_user' => ['access_token' => 'xoxp-A']],
        fn (Request $r): bool => $r->url() === 'https://slack.com/api/auth.revoke' && $r->header('Authorization')[0] === 'Bearer xoxp-A'],
    'HubSpot: DELETE the refresh token by path' => ['hubspot', ['access_token' => 'CJ', 'refresh_token' => 'na1-R/x', 'expires_in' => 1800],
        fn (Request $r): bool => $r->method() === 'DELETE' && $r->url() === 'https://api.hubapi.com/oauth/v1/refresh-tokens/na1-R%2Fx'],
    'Linear: bearer revoke' => ['linear', ['access_token' => 'lin_A', 'expires_in' => 3600],
        fn (Request $r): bool => $r->url() === 'https://api.linear.app/oauth/revoke' && $r->header('Authorization')[0] === 'Bearer lin_A'],
]);

it('forgets the tokens and announces the disconnect even where the provider cannot revoke', function (string $provider, array $tokens): void {
    $events = $this->fakeEvents();
    $this->configurePipe($provider);
    $connection = $this->connectPipeAccount($provider, 'user_1', $tokens);
    Http::fake();

    expect(app(PipeConnections::class)->disconnect($connection->id, 'user_1'))->toBeFalse();
    Http::assertNothingSent();

    expect(PipeConnection::query()->count())->toBe(0)
        ->and(VaultSecret::query()->whereKey($connection->access_secret_id)->first()?->isRevoked())->toBeTrue();

    $emitted = array_values(array_filter($events->emitted, fn (DomainEvent $e): bool => $e->type === 'pipe.connection.disconnected'));
    expect($emitted[0]->payload ?? null)->toBe(['connection_id' => $connection->id, 'user_id' => 'user_1', 'provider' => $provider, 'revoked_at_provider' => false]);
})->with([
    'Microsoft 365' => ['microsoft', ['access_token' => 'eyJ', 'refresh_token' => 'M.R', 'expires_in' => 3600]],
    'Notion' => ['notion', ['access_token' => 'secret_A', 'workspace_name' => 'Acme']],
]);

it('still disconnects locally when the provider is down', function (): void {
    $this->configurePipe('google');
    $connection = $this->connectPipeAccount('google', 'user_1', ['access_token' => 'ya29', 'refresh_token' => 'r', 'expires_in' => 3600]);
    Http::fake(['*' => Http::response('', 503)]);

    expect(app(PipeConnections::class)->disconnect($connection->id, 'user_1'))->toBeFalse()
        ->and(PipeConnection::query()->count())->toBe(0)
        ->and(VaultSecret::query()->whereKey($connection->refresh_secret_id)->first()?->isRevoked())->toBeTrue();
});

it('lets the person connect again after disconnecting', function (): void {
    $this->configurePipe('github');
    $first = $this->connectPipeAccount('github', 'user_1', ['access_token' => 'gho_1']);
    Http::fake();
    app(PipeConnections::class)->disconnect($first->id, 'user_1');

    $second = $this->connectPipeAccount('github', 'user_1', ['access_token' => 'gho_2']);

    expect($second->id)->not->toBe($first->id)
        ->and($second->access_secret_id)->not->toBe($first->access_secret_id);
});

it('erases a person\'s connections and their tokens with them', function (): void {
    $this->configurePipe('google');
    $connection = $this->connectPipeAccount('google', 'user_gone', ['access_token' => 'ya29', 'refresh_token' => 'r', 'expires_in' => 3600]);
    $this->configurePipe('github');
    $kept = $this->connectPipeAccount('github', 'user_kept', ['access_token' => 'gho']);

    $steps = collect(app(ErasureSteps::class)->all())->keyBy(fn ($step): string => $step->name());
    expect($steps)->toHaveKeys(['pipes.connections', 'token_vault.secrets']);

    $request = new ErasureRequest('user_gone', null, null, SubjectPseudonym::fromToken('t'), AuditActor::system());
    $steps['pipes.connections']->erase($request);
    $steps['token_vault.secrets']->erase($request);

    expect(PipeConnection::query()->pluck('id')->all())->toBe([$kept->id])
        ->and(VaultSecret::query()->whereKey($connection->access_secret_id)->exists())->toBeFalse()
        ->and(VaultSecret::query()->whereKey($connection->refresh_secret_id)->exists())->toBeFalse();
});
