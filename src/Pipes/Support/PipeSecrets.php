<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Support;

use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Cbox\Id\Pipes\Models\Pipe;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\ValueObjects\SecretLease;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Support\Str;

/**
 * Where Pipes keeps its secrets, in one place.
 *
 *  - The pipe's OAuth CLIENT secret is a sealed column on the pipe row
 *    ({@see Pipe::secretContext()}), registered with the master-key rewrap.
 *  - A person's access and refresh tokens are TOKEN-VAULT secrets owned by that person.
 *    Pipes reaches them only through the {@see SecretVault} contract — store, rotate,
 *    grant, lease, revoke — so they are sealed, audited and erased exactly like every
 *    other vaulted credential, and a host that swaps the vault implementation (an HSM, an
 *    external secrets manager) swaps it for Pipes too.
 *
 * ## The broker client
 *
 * The vault is deny-by-default per (secret, client). Each connection's two secrets carry
 * ONE grant, to {@see self::BROKER_CLIENT_ID}: Pipes itself. Every read of a person's token
 * — to refresh it, to revoke it, or to hand it to an app — is therefore a vault lease,
 * on the vault's audit trail, with a purpose that names why (and for an app's lease,
 * which app). Apps never hold vault grants on these secrets; whether an app may have a
 * token is the pipe's grant list, checked before the lease is taken.
 *
 * The id cannot collide with a real app: registered clients are `cid_…` ULIDs and
 * metadata-document clients are https URLs, and this is neither. Even so, the owner scope
 * holds: these secrets are user-owned, and the vault API only ever addresses organization-
 * and environment-owned ones.
 */
class PipeSecrets
{
    public const string BROKER_CLIENT_ID = 'cbox-id:pipes';

    public function __construct(
        private readonly SecretVault $vault,
        private readonly SecretBox $secretBox,
    ) {}

    public function sealClientSecret(Pipe $pipe, string $secret): void
    {
        $pipe->client_secret_encrypted = $this->secretBox->seal($secret, $pipe->secretContext());
    }

    public function clientSecret(Pipe $pipe): string
    {
        return $this->secretBox->open($pipe->client_secret_encrypted, $pipe->secretContext());
    }

    /**
     * Vault a token for a person and grant the broker. Returns the secret id.
     */
    public function store(Pipe $pipe, string $userId, string $kind, string $token): string
    {
        $owner = VaultOwner::user($userId);

        // Unique per connect, not per connection: a revoked vault secret keeps its name, so
        // a stable name would collide the first time somebody reconnected.
        $secret = $this->vault->store(
            'pipe:'.$pipe->provider.':'.$kind.':'.Str::lower((string) Str::ulid()),
            $pipe->provider,
            $token,
            $owner,
        );

        $this->vault->grant($secret->id, self::BROKER_CLIENT_ID, $owner);

        return $secret->id;
    }

    public function rotate(string $secretId, string $userId, string $token): void
    {
        $this->vault->rotate($secretId, $token, VaultOwner::user($userId));
    }

    /**
     * Open a person's token through the vault, as the broker. `$purpose` lands on the
     * vault's audit trail — never the value.
     */
    public function open(string $secretId, string $userId, string $purpose): string
    {
        return $this->lease($secretId, $userId, $purpose)->secret;
    }

    /**
     * The same lease, keeping the vault's advisory window — what an app's lease reports.
     */
    public function lease(string $secretId, string $userId, string $purpose): SecretLease
    {
        return $this->vault->lease($secretId, self::BROKER_CLIENT_ID, $purpose, VaultOwner::user($userId));
    }

    public function revoke(?string $secretId, string $userId): void
    {
        if ($secretId === null) {
            return;
        }

        try {
            $this->vault->revoke($secretId, VaultOwner::user($userId));
        } catch (SecretNotFound) {
            // Already gone — erased with the person, most likely. Nothing left to revoke.
        }
    }
}
