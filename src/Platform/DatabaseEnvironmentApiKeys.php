<?php

declare(strict_types=1);

namespace Cbox\Id\Platform;

use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentContext;
use Cbox\Id\Kernel\Tenancy\GenericEnvironment;
use Cbox\Id\Platform\Contracts\EnvironmentApiKeys;
use Cbox\Id\Platform\Models\EnvironmentApiKey;
use Cbox\Id\Platform\ValueObjects\IssuedEnvironmentApiKey;
use DateTimeInterface;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/**
 * Eloquent-backed environment API keys. The token is high-entropy random with a
 * recognisable `cbid_env_` prefix; only its SHA-256 hash is stored and lookup is by
 * that hash, so a wrong token simply doesn't match (no timing oracle). The model is
 * hard environment-scoped, so `resolve()` — which runs inside the request's already
 * host-resolved environment — can only ever return a key that belongs to it; a key
 * from another environment is invisible, not merely rejected.
 *
 * Management calls that arrive without an ambient environment (issue/list/revoke
 * from the account console) run inside the target environment via {@see runAs}.
 */
final class DatabaseEnvironmentApiKeys implements EnvironmentApiKeys
{
    /**
     * Brand root `cbid` + plane marker `env`, so a leaked key is identifiable at a
     * glance and never confusable with an account-plane credential (`cbid_acc_`).
     */
    private const PREFIX = 'cbid_env_';

    public function __construct(private readonly EnvironmentContext $context) {}

    public function issue(string $environmentId, string $name, array $scopes, ?DateTimeInterface $expiresAt = null): IssuedEnvironmentApiKey
    {
        $plaintext = self::PREFIX.Str::random(40);

        $key = $this->context->runAs(GenericEnvironment::of($environmentId), fn (): EnvironmentApiKey => EnvironmentApiKey::query()->create([
            'environment_id' => $environmentId,
            'name' => $name,
            // A non-secret fragment so the key is identifiable in a list.
            'prefix' => substr($plaintext, 0, 13),
            'token_hash' => $this->hash($plaintext),
            'scopes' => $scopes,
            'expires_at' => $expiresAt,
        ]));

        return new IssuedEnvironmentApiKey($key, $plaintext);
    }

    public function resolve(string $plaintext): ?EnvironmentApiKey
    {
        // Cheap shape check before touching the database — a token that can't be
        // ours never triggers a lookup.
        if (! str_starts_with($plaintext, self::PREFIX)) {
            return null;
        }

        // No explicit environment filter: the hard scope constrains the lookup to
        // the current (host-resolved) environment, so a cross-environment key is
        // simply not found.
        $key = EnvironmentApiKey::query()->where('token_hash', $this->hash($plaintext))->first();

        if ($key === null || ! $key->isActive()) {
            return null;
        }

        $key->forceFill(['last_used_at' => now()])->save();

        return $key;
    }

    public function revoke(string $environmentId, string $id): void
    {
        $this->context->runAs(GenericEnvironment::of($environmentId), function () use ($id): void {
            EnvironmentApiKey::query()->whereKey($id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
        });
    }

    public function forEnvironment(string $environmentId): Collection
    {
        // ULIDs are monotonic, so ordering by id is newest-first AND deterministic
        // even for keys minted within the same clock tick.
        return $this->context->runAs(
            GenericEnvironment::of($environmentId),
            fn (): Collection => EnvironmentApiKey::query()->orderByDesc('id')->get(),
        );
    }

    private function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }
}
