<?php

declare(strict_types=1);

namespace Cbox\Id\FrontendApi;

use Cbox\Id\FrontendApi\Contracts\PublishableKeys;
use Cbox\Id\FrontendApi\Enums\KeyMode;
use Cbox\Id\FrontendApi\Exceptions\UnusableOrigin;
use Cbox\Id\FrontendApi\Models\AllowedOrigin;
use Cbox\Id\FrontendApi\Models\PublishableKey;
use Cbox\Id\FrontendApi\Support\Origin;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * The default {@see PublishableKeys}, over the two tables.
 */
class DatabasePublishableKeys implements PublishableKeys
{
    /** 32 base62 after the prefix — ~190 bits, and short enough to read aloud in support. */
    private const ENTROPY = 32;

    public function issue(string $name, KeyMode $mode, array $origins): PublishableKey
    {
        $normalized = $this->normalizeAll($origins);

        // ONE TRANSACTION, because a key without its origins is a key that works nowhere.
        // Half of this succeeding is the state a person copies into a bundle before
        // discovering it is inert.
        return DB::transaction(function () use ($name, $mode, $normalized): PublishableKey {
            $key = PublishableKey::query()->create([
                'key' => $mode->prefix().Str::random(self::ENTROPY),
                'mode' => $mode,
                'name' => $name,
            ]);

            foreach ($normalized as $origin) {
                $key->origins()->create(['origin' => $origin]);
            }

            return $key->load('origins');
        });
    }

    public function resolve(string $key): ?PublishableKey
    {
        // Shape first, so a junk string never reaches the database. It also means the
        // common attack — spraying values at the endpoint — costs a string comparison.
        if (KeyMode::fromKey($key) === null) {
            return null;
        }

        $found = PublishableKey::query()
            ->with('origins')
            ->where('key', $key)
            ->whereNull('revoked_at')
            ->first();

        return $found instanceof PublishableKey ? $found : null;
    }

    public function allowsOrigin(string $origin): bool
    {
        $normalized = Origin::normalize($origin);

        if ($normalized === null) {
            return false;
        }

        // FROM THE ORIGINS TABLE INWARD, because that is the side the index is on.
        // Driving this from `frontend_api_keys` and filtering with `whereHas` makes the
        // origin the inner predicate, so a NON-matching origin — the case an anonymous
        // caller controls — walks every active key in the environment. Started from the
        // indexed column, a miss is one probe.
        //
        // Origins are normalized on the way in AND stored normalized, so this stays the
        // exact comparison {@see PublishableKey::allowsOrigin()} makes. The database does
        // it here only because a preflight carries no key to load an allow-list from.
        return AllowedOrigin::query()
            ->where('origin', $normalized)
            ->whereHas('key', static fn (Builder $query): Builder => $query->whereNull('revoked_at'))
            ->exists();
    }

    public function revoke(string $id): void
    {
        // `whereNull` so re-revoking keeps the original timestamp: when a key stopped
        // working is a fact somebody will need during an incident, and overwriting it with
        // the time of the second click destroys it.
        PublishableKey::query()
            ->whereKey($id)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()]);
    }

    public function setOrigins(string $id, array $origins): void
    {
        $normalized = $this->normalizeAll($origins);

        $key = PublishableKey::query()->whereKey($id)->first();

        if (! $key instanceof PublishableKey) {
            return;
        }

        DB::transaction(function () use ($key, $normalized): void {
            $key->origins()->delete();

            foreach ($normalized as $origin) {
                $key->origins()->create(['origin' => $origin]);
            }
        });
    }

    /**
     * Normalize every origin, refuse anything unusable, and drop duplicates.
     *
     * Refusing rather than skipping: see {@see UnusableOrigin}. Plain `http` is refused
     * away from loopback, because a key travelling in the clear is a key anybody on the
     * path can lift — and the whole security of this scheme is that the key is useless
     * without an origin somebody had to name.
     *
     * @param  list<string>  $origins
     * @return list<string>
     */
    private function normalizeAll(array $origins): array
    {
        $normalized = [];

        foreach ($origins as $raw) {
            $origin = Origin::normalize($raw);

            if ($origin === null) {
                throw UnusableOrigin::for($raw);
            }

            if (str_starts_with($origin, 'http://') && ! Origin::isLoopback($origin)) {
                throw UnusableOrigin::insecure($origin);
            }

            $normalized[$origin] = true;
        }

        return array_keys($normalized);
    }
}
