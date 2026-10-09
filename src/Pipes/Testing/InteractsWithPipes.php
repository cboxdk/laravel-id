<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Testing;

use Cbox\Id\Pipes\Contracts\PipeConnections;
use Cbox\Id\Pipes\Contracts\Pipes;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\Pipes\Models\PipeConnection;
use Cbox\Id\Pipes\PipeProviderCatalog;
use Cbox\Id\Pipes\ValueObjects\PipeAccessToken;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Http;

/**
 * Test ergonomics for Pipes, shipped with the package so a host app's suite connects
 * accounts the same way the package's own does — through the REAL connect flow, with only
 * the provider faked:
 *
 *     uses(InteractsWithPipes::class);
 *
 *     it('lists my GitHub repositories', function () {
 *         $pipe = $this->configurePipe('github');
 *         $this->grantPipe($pipe, 'cid_my_app');
 *         $this->connectPipeAccount('github', 'user_1', ['access_token' => 'gho_test']);
 *
 *         $token = $this->leasePipeToken('github', 'user_1', 'cid_my_app');
 *         expect($token->accessToken)->toBe('gho_test');
 *     });
 *
 * Outbound host verification is switched off for the pipes ({@see self::configurePipe()}),
 * because a faked provider has no address to verify.
 */
trait InteractsWithPipes
{
    /**
     * @param  list<string>|null  $scopes
     * @param  array<string, string>  $parameters
     */
    protected function configurePipe(string $provider = 'github', ?array $scopes = null, string $clientId = 'pipe-client-id', string $clientSecret = 'pipe-client-secret', array $parameters = []): Pipe
    {
        config(['cbox-id.pipes.verify_url' => false]);

        return app(Pipes::class)->configure($provider, $clientId, $clientSecret, $scopes, $parameters);
    }

    protected function grantPipe(Pipe $pipe, string $clientId): void
    {
        app(Pipes::class)->grant($pipe->id, $clientId);
    }

    /**
     * Connect `$userId`'s account through the real start → callback flow, with the
     * provider's token endpoint answering `$tokenResponse`.
     *
     * It runs against its OWN HTTP fakes and leaves none behind (a fake registered for the
     * same URL would otherwise shadow the other), so register the fakes your test asserts
     * on after calling it.
     *
     * @param  array<string, mixed>  $tokenResponse
     */
    protected function connectPipeAccount(string $provider, string $userId, array $tokenResponse, string $redirectUri = 'https://id.test/pipes/callback'): PipeConnection
    {
        $pipe = app(Pipes::class)->forProvider($provider);
        $entry = PipeProviderCatalog::find($provider);

        if ($pipe === null || $entry === null) {
            throw new \LogicException("Configure the {$provider} pipe before connecting an account through it.");
        }

        $tokenUrl = $entry->endpoint($entry->tokenEndpoint, $pipe->parameterValues());
        $fakes = [$tokenUrl => Http::response($tokenResponse)];

        if ($entry->accountEndpoint !== null) {
            $fakes[$entry->endpoint($entry->accountEndpoint, $pipe->parameterValues())] = Http::response([]);
        }

        Http::swap(new HttpFactory(app(Dispatcher::class)));
        Http::fake($fakes);

        $connections = app(PipeConnections::class);
        $authorization = $connections->start($provider, $userId, $redirectUri);

        try {
            return $connections->complete($authorization->state, $authorization->state->state, 'test-code');
        } finally {
            Http::swap(new HttpFactory(app(Dispatcher::class)));
        }
    }

    protected function leasePipeToken(string $provider, string $userId, string $clientId, string $purpose = 'test'): PipeAccessToken
    {
        return app(PipeTokens::class)->lease($provider, $userId, $clientId, $purpose);
    }
}
