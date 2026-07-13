<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Crypto\Console;

use Cbox\Id\Kernel\Crypto\Contracts\KeyManager;
use Cbox\Id\Kernel\Crypto\Enums\KeyStatus;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Cbox\Id\Kernel\Crypto\Models\SigningKey;
use Illuminate\Console\Command;

/**
 * Rotates the active signing key and (optionally) retires keys that have been in
 * the `Rotating` overlap window longer than needed. Schedule it — e.g. rotate
 * every 90 days and retire `Rotating` keys older than the longest token TTL, so a
 * compromised or simply aged key stops signing without breaking in-flight tokens.
 */
final class RotateKeysCommand extends Command
{
    protected $signature = 'cbox-id:keys:rotate {--alg=RS256 : Signing algorithm (RS256|ES256|EdDSA)} {--retire-after= : Retire Rotating keys older than this many hours}';

    protected $description = 'Rotate the active signing key and optionally retire stale rotating keys';

    public function handle(KeyManager $keys): int
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

        $new = $keys->rotate($alg);
        $this->info("Rotated {$alg->value}: new active kid {$new->kid} (previous key now in the overlap window).");

        $retireAfter = $this->option('retire-after');

        if (is_numeric($retireAfter)) {
            $retired = $this->retireStale($keys, (int) $retireAfter);
            $this->info("Retired {$retired} rotating key(s) older than {$retireAfter}h.");
        }

        return self::SUCCESS;
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
