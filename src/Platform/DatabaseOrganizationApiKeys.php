<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Identity\DatabaseSessionManager;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Platform\Contracts\OrganizationApiKeys;
use Cbox\Id\Platform\Models\OrganizationApiKey;
use Cbox\Id\Platform\ValueObjects\IssuedOrganizationApiKey;
use DateTimeInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Eloquent-backed organization API keys. The token is a high-entropy random string with
 * a recognisable `cbid_org_` prefix; only its SHA-256 hash is stored, and lookup is
 * by that hash — a wrong token simply doesn't match, so there is no verification
 * timing oracle to exploit (unlike a per-record password compare).
 */
class DatabaseOrganizationApiKeys implements OrganizationApiKeys
{
    /**
     * How long a `last_used_at` write is skipped after the last one, in seconds.
     *
     * The same window {@see DatabaseSessionManager::TOUCH_THROTTLE_SECONDS}
     * and the Frontend API door use. It is a column an operator reads before revoking a
     * key, not a real-time counter.
     */
    private const TOUCH_THROTTLE_SECONDS = 60;

    public function __construct(
        private readonly PlatformRoot $platformRoot,
    ) {}

    /**
     * Brand root `cbid` (Cbox ID) + plane marker `org` (the management plane, which an
     * organization owns), so a leaked key is identifiable at a glance and never confusable
     * with an environment-plane credential (which carries `cbid_env_`).
     *
     * It was `cbid_acc_` — the account plane's marker — and changing it is a breaking change
     * to a user-visible credential format, which is exactly why it happens now: there is one
     * release ahead, keys are re-minted after migrate:fresh, and no deployment carries an
     * old key across. After 1.0.0 the prefix would name a plane that has not existed since
     * before the first tag.
     */
    private const PREFIX = 'cbid_org_';

    public function issue(string $organizationId, string $name, MembershipRole $role, ?DateTimeInterface $expiresAt = null): IssuedOrganizationApiKey
    {
        $plaintext = self::PREFIX.Str::random(40);

        $key = OrganizationApiKey::query()->create([
            'organization_id' => $organizationId,
            'name' => $name,
            // A non-secret fragment so the key is identifiable in a list.
            'prefix' => substr($plaintext, 0, 12),
            'token_hash' => $this->hash($plaintext),
            'role' => $role,
            'expires_at' => $expiresAt,
        ]);

        return new IssuedOrganizationApiKey($key, $plaintext);
    }

    public function resolve(string $plaintext): ?OrganizationApiKey
    {
        // Cheap shape check before touching the database — a token that can't be
        // ours never triggers a lookup.
        if (! str_starts_with($plaintext, self::PREFIX)) {
            return null;
        }

        $key = OrganizationApiKey::query()->where('token_hash', $this->hash($plaintext))->first();

        // The key must be live AND its organization active — a suspended organization's
        // keys stop working, so a delinquent or compromised customer cannot keep driving
        // the management API.
        //
        // THE STATUS READ RUNS IN THE PLATFORM ROOT, which the account plane never had to
        // think about: `accounts` sat outside tenancy, so `$key->account` resolved from
        // anywhere. `organizations` is environment-owned, so the same expression written
        // the same way resolves to null on every host but one — and null here reads as
        // "not active", which would refuse every valid key on every tenant host. Silently,
        // and only in production, because a test that never leaves the root cannot see it.
        if ($key === null || ! $key->isActive()) {
            return null;
        }

        // `revokesAccess()`, not an `isActive()` on the model. `Account::isActive()` was
        // `status === Active` against a two-case enum, so the two were the same thing;
        // `OrganizationStatus` has a third case, and `Deleted` must refuse a key exactly as
        // `Suspended` does. Re-deriving that decision here would be the second place it
        // lives — the precise mistake {@see OrganizationStatus::revokesAccess()} was written
        // to stop, and it reads as "allowed" for whichever case somebody adds next.
        //
        // A key whose organization cannot be produced is refused, like a missing status.
        $organizationIsActive = $this->platformRoot->run(
            fn (): bool => $key->organization?->status->revokesAccess() === false,
        ) ?? false;

        if (! $organizationIsActive) {
            return null;
        }

        // THROTTLED, like every other `last_used_at` in this package
        // ({@see \Cbox\Id\FrontendApi\Http\Middleware\AuthenticateFrontendApi::touch()},
        // {@see \Cbox\Id\Identity\DatabaseSessionManager::TOUCH_THROTTLE_SECONDS}). It is a
        // column nobody reads in real time — it tells an operator whether a key is still
        // wired into something before they revoke it — and writing it on every request
        // turns a customer polling a read endpoint into a write on one hot row, with the
        // lock contention that implies.
        if ($key->last_used_at === null || $key->last_used_at->diffInSeconds(now()) >= self::TOUCH_THROTTLE_SECONDS) {
            $key->forceFill(['last_used_at' => now()])->save();
        }

        return $key;
    }

    public function revoke(string $id): void
    {
        OrganizationApiKey::query()->whereKey($id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
    }

    public function forOrganization(string $organizationId): Collection
    {
        // ULIDs are monotonic, so ordering by id is newest-first AND deterministic
        // even for keys minted within the same clock tick.
        return OrganizationApiKey::query()
            ->where('organization_id', $organizationId)
            ->orderByDesc('id')
            ->get();
    }

    private function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }
}
