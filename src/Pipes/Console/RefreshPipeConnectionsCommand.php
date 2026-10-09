<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Console;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Pipes\Contracts\PipeTokens;
use Cbox\Id\Pipes\Enums\PipeConnectionStatus;
use Cbox\Id\Pipes\Exceptions\PipeConnectionNotFound;
use Cbox\Id\Pipes\Exceptions\PipeRefreshFailed;
use Cbox\Id\Pipes\Models\PipeConnection;
use Illuminate\Console\Command;

/**
 * Refresh every connected account whose access token expires soon, so an app's lease is
 * almost always a read rather than a round trip to the provider.
 *
 * The sweep is an optimisation, not the guarantee: a lease refreshes on its own when it
 * finds the token expiring, so a stopped scheduler costs latency, not correctness. What
 * the sweep adds is finding the dead connections early — a refresh token the provider
 * revoked turns the connection `needs_reauth` and emits `pipe.connection.needs_reauth`
 * while the person can still be asked to reconnect, instead of at the moment the app
 * needed the token.
 *
 * Connections live in every environment, so the candidates are read above the scope and
 * each one is refreshed inside its own. A connection another process is refreshing is
 * skipped, not waited for.
 */
class RefreshPipeConnectionsCommand extends Command
{
    protected $signature = 'cbox-id:pipes:refresh {--limit= : At most this many connections per run}';

    protected $description = 'Refresh connected third-party accounts (Pipes) whose access tokens expire soon.';

    public function handle(EnvironmentContext $context, PipeTokens $tokens): int
    {
        $ahead = $this->intConfig('refresh_ahead_seconds', 600);
        $limitOption = $this->option('limit');
        $limit = is_numeric($limitOption) ? max(1, (int) $limitOption) : $this->intConfig('refresh_batch', 200);

        $due = $context->withoutScope(fn () => PipeConnection::query()
            ->where('status', PipeConnectionStatus::Active->value)
            ->whereNotNull('access_expires_at')
            ->where('access_expires_at', '<=', now()->addSeconds($ahead))
            ->where(fn ($query) => $query->whereNull('refresh_claimed_until')->orWhere('refresh_claimed_until', '<', now()))
            ->orderBy('access_expires_at')
            ->limit($limit)
            ->get(['id', 'environment_id']));

        $refreshed = 0;
        $failed = 0;
        $reauth = 0;

        foreach ($due as $row) {
            try {
                $connection = $context->runAs(
                    GenericEnvironment::of($row->environment_id),
                    fn (): PipeConnection => $tokens->refreshIfExpiring($row->id, $ahead),
                );

                $connection->isActive() ? $refreshed++ : $reauth++;
            } catch (PipeRefreshFailed) {
                $failed++;
            } catch (PipeConnectionNotFound) {
                // Disconnected since the query ran.
            }
        }

        $this->info("Checked {$due->count()} connection(s): {$refreshed} fresh, {$reauth} need the person to reconnect, {$failed} failed and will be retried.");

        return self::SUCCESS;
    }

    private function intConfig(string $key, int $default): int
    {
        $value = config('cbox-id.pipes.'.$key, $default);

        return is_numeric($value) ? max(1, (int) $value) : $default;
    }
}
