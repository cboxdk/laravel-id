<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Console;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * Rotates the active signing key and (optionally) retires keys that have been in
 * the `Rotating` overlap window longer than needed. Schedule it — e.g. rotate
 * every 90 days and retire `Rotating` keys older than the longest token TTL, so a
 * compromised or simply aged key stops signing without breaking in-flight tokens.
 *
 * PER ENVIRONMENT, AND THAT IS THE WHOLE OF THIS CLASS'S DIFFICULTY.
 *
 * `SigningKey` is environment-owned and `EnvironmentScope` is deny-by-default, so a
 * query with no environment in context compiles to `1 = 0`. `SetEnvironment` is web-group
 * middleware — a scheduler or CLI run has no context at all. This command did neither
 * what the other cross-environment commands do (enumerate under `withoutScope`, then
 * `runAs` per environment) nor anything to notice:
 *
 *   - `rotate()`'s `UPDATE ... where status = Active` matched nothing, so the key an
 *     operator was rotating AWAY from stayed Active;
 *   - `generate()` then wrote a row with no `environment_id` into a NOT NULL column and
 *     the command died on a QueryException;
 *   - `--retire-after` compiled to `1 = 0` and printed "Retired 0 rotating key(s)", which
 *     reads as "there were none" rather than "I could not see any".
 *
 * Measured before the fix, from a context-less run against a seeded environment: the
 * command threw, no key was generated, and the original key was still Active afterwards.
 * That is the response to a suspected key compromise, and it did nothing while reporting
 * that it had.
 */
class RotateKeysCommand extends Command
{
    protected $signature = 'cbox-id:keys:rotate {--alg=RS256 : Signing algorithm (RS256|ES256|EdDSA)} {--retire-after= : Retire Rotating keys older than this many hours} {--environment= : Rotate only this environment (default: every environment holding keys)}';

    protected $description = 'Rotate the active signing key and optionally retire stale rotating keys';

    public function handle(KeyManager $keys, EnvironmentContext $context): int
    {
        $algOption = $this->option('alg');
        $algOption = is_string($algOption) ? $algOption : 'RS256';

        // Match case-insensitively so "eddsa"/"EDDSA" resolve to the EdDSA case.
        $alg = collect(SigningAlg::cases())
            ->first(fn (SigningAlg $a): bool => strcasecmp($a->value, $algOption) === 0);

        if (! $alg instanceof SigningAlg) {
            $this->error("Unknown algorithm [{$algOption}]. Use RS256, ES256 or EdDSA.");

            return self::FAILURE;
        }

        $retireAfter = $this->option('retire-after');
        $environments = $this->environments($context);

        if ($environments === []) {
            // Said out loud rather than reported as a successful no-op, because "nothing
            // to rotate" and "I cannot see anything to rotate" look identical in a log
            // and mean opposite things to whoever is responding to a compromise.
            $this->warn('No environments found — nothing was rotated.');

            return self::SUCCESS;
        }

        foreach ($environments as $environmentId) {
            $context->runAs(GenericEnvironment::of($environmentId), function () use ($keys, $alg, $retireAfter, $environmentId): void {
                $new = $keys->rotate($alg);
                $this->info("[{$environmentId}] Rotated {$alg->value}: new active kid {$new->kid} (previous key now in the overlap window).");

                if (is_numeric($retireAfter)) {
                    $retired = $this->retireStale($keys, (int) $retireAfter);
                    $this->info("[{$environmentId}] Retired {$retired} rotating key(s) older than {$retireAfter}h.");
                }
            });
        }

        return self::SUCCESS;
    }

    /**
     * Every environment that holds signing keys, or the one named by `--environment`.
     *
     * Read under `withoutScope()` because cross-environment enumeration is a system
     * operation — the same escape the audit-stream, provisioning, governance and
     * retention commands use, and for the same reason.
     *
     * Taken from `signing_keys` rather than from an environments table so the kernel does
     * not reach up into the Organization module for a list it can derive from its own.
     *
     * @return list<string>
     */
    private function environments(EnvironmentContext $context): array
    {
        $only = $this->option('environment');

        if (is_string($only) && $only !== '') {
            return [$only];
        }

        /** @var list<string> $ids */
        $ids = $context->withoutScope(
            static fn (): array => array_values(array_filter(
                DB::table('signing_keys')->distinct()->pluck('environment_id')->all(),
                is_string(...),
            )),
        );

        return $ids;
    }

    private function retireStale(KeyManager $keys, int $hours): int
    {
        $cutoff = now()->subHours($hours);
        $count = 0;

        SigningKey::query()
            ->where('status', KeyStatus::Rotating->value)
            ->where('updated_at', '<', $cutoff)
            ->each(function (SigningKey $key) use ($keys, &$count): void {
                $keys->retire($key->kid);
                $count++;
            });

        return $count;
    }
}
