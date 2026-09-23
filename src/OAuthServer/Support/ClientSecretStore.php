<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Support;

use Carbon\CarbonImmutable;
use Cbox\Id\OAuthServer\Contracts\ClientRegistry;
use Cbox\Id\OAuthServer\Models\Client;
use Cbox\Id\OAuthServer\Models\StoredClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\ClientSecret;
use Cbox\Id\OAuthServer\ValueObjects\IssuedClientSecret;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;

/**
 * Where a client's secrets live: `oauth_client_secrets`, one row per secret, any live one
 * authenticates.
 *
 * The mechanics only — no policy, no audit. {@see ClientRegistry} decides WHETHER a
 * client may rotate or revoke and records that it did; this class is what both it and the
 * RFC 7592 management path use to do it, so there is one place a secret is written and
 * one place it is compared.
 *
 * THE LEGACY COLUMN. `oauth_clients.secret_hash` is kept for 1.19 as a mirror of the
 * newest live secret, written here after every change and never read to authenticate.
 * It is written with a query rather than a model save, so the model's own hook — which
 * adopts a hash a host wrote to that column the pre-1.19 way — does not see this class's
 * writes as a host's.
 */
class ClientSecretStore
{
    /**
     * How long a `last_used_at` write is skipped after the last one, in seconds — the
     * same window every other `last_used_at` in this package uses. A client polling the
     * token endpoint must not turn every request into a write on one hot row.
     */
    private const TOUCH_THROTTLE_SECONDS = 60;

    /**
     * Mint a new secret for the client and store its hash. The plaintext exists only in
     * the returned value.
     */
    public function issue(Client $client): IssuedClientSecret
    {
        $minted = ClientSecret::mint();

        $stored = new StoredClientSecret;
        $stored->fill([
            'environment_id' => $client->environment_id,
            'oauth_client_id' => $client->id,
            'secret_hash' => $minted->hash,
            'hint' => $minted->hint(),
        ]);
        $stored->save();

        $this->syncMirror($client);

        return new IssuedClientSecret($minted, $stored);
    }

    /**
     * Does the presented secret match ANY live secret of this client?
     *
     * Every live secret is compared, and in constant time, whether or not an earlier one
     * already matched — so how long this takes says nothing about which of a client's
     * secrets was presented or how close a guess came.
     */
    public function verify(Client $client, string $plaintext): bool
    {
        $presented = ClientSecret::hash($plaintext);
        $matched = null;

        foreach ($this->live($client) as $secret) {
            if (hash_equals($secret->secret_hash, $presented) && $matched === null) {
                $matched = $secret;
            }
        }

        if ($matched === null) {
            return false;
        }

        if ($matched->last_used_at === null || $matched->last_used_at->diffInSeconds(now()) >= self::TOUCH_THROTTLE_SECONDS) {
            // A query, not a save: `updated_at` means "the secret changed", not "it was used".
            DB::table('oauth_client_secrets')->where('id', $matched->id)->update(['last_used_at' => now()]);
        }

        return true;
    }

    public function hasLive(Client $client): bool
    {
        return $this->forClient($client)->live()->exists();
    }

    /**
     * The client's live secrets, newest first.
     *
     * @return Collection<int, StoredClientSecret>
     */
    public function live(Client $client): Collection
    {
        return $this->forClient($client)
            ->live()
            ->orderByDesc('created_at')
            ->orderByDesc('id')
            ->get();
    }

    public function find(Client $client, string $secretId): ?StoredClientSecret
    {
        // Bound to the client IN THE QUERY: a secret id from another client is not found,
        // rather than found and then refused.
        return $this->forClient($client)->live()->whereKey($secretId)->first();
    }

    /**
     * Give every live secret except `$keepId` an expiry no later than `$at`, and delete the
     * ones that are already past theirs. A rotation never EXTENDS a secret: one that was
     * already due to expire sooner keeps the earlier time.
     */
    public function retireAllExcept(Client $client, string $keepId, CarbonImmutable $at): void
    {
        $this->forClient($client)
            ->whereKeyNot($keepId)
            ->where(fn (Builder $q): Builder => $q->whereNull('expires_at')->orWhere('expires_at', '>', $at))
            ->update(['expires_at' => $at]);

        $this->prune($client);
        $this->syncMirror($client);
    }

    public function revoke(Client $client, StoredClientSecret $secret): void
    {
        $this->forClient($client)->whereKey($secret->id)->delete();

        $this->syncMirror($client);
    }

    /**
     * Remove every secret the client has — for a client that no longer authenticates
     * with a shared secret at all.
     */
    public function revokeAll(Client $client): void
    {
        $this->forClient($client)->delete();

        $this->syncMirror($client);
    }

    /**
     * Adopt a hash a host wrote straight to `oauth_clients.secret_hash` — the only way to
     * rotate a secret before 1.19, and what code built against 1.18 still does.
     *
     * It gets the semantics it had then: the written hash becomes the client's ONE secret,
     * effective immediately, and null means no secret. Doing nothing instead would make
     * that host's rotation silently inert — the new secret refused and the old one still
     * working — which is the worst of both.
     */
    public function adoptLegacyHash(Client $client): void
    {
        $hash = $client->secret_hash;

        if ($hash === null || $hash === '') {
            $this->forClient($client)->delete();

            return;
        }

        $alreadyLive = $this->forClient($client)->live()->where('secret_hash', $hash)->exists();

        if ($alreadyLive) {
            return;
        }

        $this->forClient($client)->delete();

        $stored = new StoredClientSecret;
        $stored->fill([
            'environment_id' => $client->environment_id,
            'oauth_client_id' => $client->id,
            'secret_hash' => $hash,
            'hint' => null,
        ]);
        $stored->save();
    }

    /** Drop the rows that can no longer authenticate. */
    private function prune(Client $client): void
    {
        $this->forClient($client)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->delete();
    }

    /**
     * Keep the deprecated `oauth_clients.secret_hash` equal to the newest live secret's
     * hash, or null when there is none. Read by nothing in this package; kept so a host
     * that reads it does not break before it is dropped.
     */
    private function syncMirror(Client $client): void
    {
        $newest = $this->live($client)->first()?->secret_hash;

        DB::table('oauth_clients')->where('id', $client->id)->update(['secret_hash' => $newest]);

        $client->setAttribute('secret_hash', $newest);
        $client->syncOriginalAttribute('secret_hash');
    }

    /**
     * @return Builder<StoredClientSecret>
     */
    private function forClient(Client $client): Builder
    {
        return StoredClientSecret::query()->where('oauth_client_id', $client->id);
    }
}
