<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Console;

use Cbox\Id\AuditStreaming\Jobs\PumpAuditStream;
use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Illuminate\Console\Command;

/**
 * Fan a pump job out to every enabled audit stream in EVERY environment.
 *
 * This is the ONE genuinely environment-spanning system step, and it is careful to
 * be only a dispatcher: under {@see EnvironmentContext::withoutScope()} it
 * enumerates all enabled streams across the whole deployment and dispatches one
 * {@see PumpAuditStream} per stream. It never delivers and never reads a delivery
 * row across the boundary — each dispatched job re-enters its own stream's
 * environment before touching any outbox data. Scheduled every minute by the
 * service provider (laravel-id owns SIEM scheduling; laravel-siem's own scheduler
 * is disabled), or run by hand.
 */
class PumpAuditStreamsCommand extends Command
{
    protected $signature = 'cbox-id:audit-streams:pump';

    protected $description = 'Dispatch a delivery pump for every enabled audit stream across all environments.';

    public function handle(EnvironmentContext $context): int
    {
        // Cross-environment enumeration is a system operation — suspend the hard
        // scope to see every environment's streams, then dispatch (never deliver).
        $streamIds = $context->withoutScope(
            fn (): array => AuditStream::query()
                ->where('enabled', true)
                ->pluck('id')
                ->all(),
        );

        foreach ($streamIds as $streamId) {
            if (is_string($streamId)) {
                PumpAuditStream::dispatch($streamId);
            }
        }

        $this->info(sprintf('Dispatched %d audit-stream pump job(s).', count($streamIds)));

        return self::SUCCESS;
    }
}
