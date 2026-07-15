<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Testing;

use Cbox\Id\AuditStreaming\Jobs\PumpAuditStream;
use Cbox\LaravelSiem\Contracts\LogStreams;
use Cbox\LaravelSiem\Enums\AuthScheme;
use Cbox\LaravelSiem\Enums\Destination;
use Cbox\LaravelSiem\ValueObjects\RegisteredStream;
use Cbox\Siem\Contracts\StreamSink;
use Cbox\Siem\Testing\FakeStreamSink;
use Illuminate\Support\Facades\Artisan;

/**
 * Test ergonomics for the audit-streaming binding. Ships with the package so a
 * host gets the same fluency: register an env-owned stream, swap the real HTTP
 * sink for an in-memory {@see FakeStreamSink}, and drive delivery synchronously —
 * either the full pump (dispatch → per-stream reconstruction → delivery) or one
 * stream directly.
 *
 * A registered stream is stamped with the CURRENT test environment automatically
 * (the model is env-owned), so `runAsEnvironment('env_b', fn () =>
 * $this->registerAuditStream(...))` creates a stream owned by env B.
 */
trait InteractsWithAuditStreaming
{
    protected ?FakeStreamSink $fakeAuditSink = null;

    /**
     * Bind an in-memory {@see FakeStreamSink} as the {@see StreamSink} so delivery
     * lands in memory instead of over HTTP.
     */
    protected function fakeAuditStreamSink(): FakeStreamSink
    {
        $fake = $this->fakeAuditSink ??= new FakeStreamSink;

        app()->instance(StreamSink::class, $fake);

        return $fake;
    }

    /**
     * Register an audit stream in the current environment. Reuses the engine's
     * registry through the env-owned model, so no bespoke create path is needed.
     */
    protected function registerAuditStream(
        string $name,
        Destination $destination = Destination::SplunkHec,
        string $endpointUrl = 'https://siem.example.com/services/collector',
        ?string $secret = 'test-token',
        ?AuthScheme $auth = null,
    ): RegisteredStream {
        return app(LogStreams::class)->create($name, $destination, $endpointUrl, $secret, $auth);
    }

    /**
     * Run the full fan-out pump (cross-environment enumeration → per-stream
     * environment reconstruction → synchronous delivery).
     */
    protected function pumpAuditStreams(): void
    {
        Artisan::call('cbox-id:audit-streams:pump');
    }

    /**
     * Pump a single stream, reconstructing its environment as the async job does.
     */
    protected function pumpAuditStream(string $streamId): void
    {
        PumpAuditStream::dispatchSync($streamId);
    }
}
