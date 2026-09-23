<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGrantable;
use Cbox\Id\OAuthServer\Support\ClientSecretStore;
use Cbox\Id\OAuthServer\ValueObjects\ScopeHolder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An OAuth client (relying party). `organization_id` names the owning org (null =
 * platform-owned, not scoped to one org); `first_party` is the explicit trust flag —
 * an org may register its OWN first-party clients, so the two are independent. Consent
 * skip must therefore be scoped: only a `first_party` client that is platform-owned OR
 * owned by the authorizing user's org may skip the consent screen (never cross-org).
 *
 * SECRETS LIVE IN `oauth_client_secrets` ({@see StoredClientSecret}), each as a SHA-256
 * hash, several at once while a rotation is in its grace period. `secret_hash` here is a
 * DEPRECATED mirror of the newest live one, kept for 1.19 so code that reads it keeps
 * working, and dropped in the next minor. Nothing authenticates against it. A host that
 * still WRITES it the pre-1.19 way — assign and save — has the write adopted as the
 * client's one secret, effective immediately, which is what that write meant then.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $client_id
 * @property string|null $secret_hash deprecated mirror of the newest live secret; see above
 * @property array<string, mixed>|null $jwks
 * @property string $name
 * @property ClientType $type
 * @property TokenEndpointAuthMethod|null $token_endpoint_auth_method
 * @property array<int, string> $redirect_uris
 * @property array<int, string>|null $post_logout_redirect_uris
 * @property string|null $backchannel_logout_uri OIDC Back-Channel Logout 1.0 §2.2 — null = never notified
 * @property bool $backchannel_logout_session_required
 * @property array<int, string> $grant_types
 * @property array<int, string> $scopes
 * @property string|null $manifest_url
 * @property int|null $access_token_ttl
 * @property string|null $api_key_prefix the prefix of this app's customer API keys; null = it accepts none
 * @property bool $first_party
 * @property string|null $registration_access_token_hash
 * @property Carbon|null $created_at
 */
class Client extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'oauth_clients';

    protected $guarded = [];

    /**
     * A credential's verifier is never serialized with the client.
     *
     * @var list<string>
     */
    protected $hidden = ['secret_hash', 'registration_access_token_hash'];

    public function allows(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * Registered through RFC 7591 rather than by an operator. Such a client is never
     * environment-owned for scope purposes, even though its `organization_id` is null
     * — see {@see ScopeHolder}.
     */
    public function isDynamicallyRegistered(): bool
    {
        return $this->registration_access_token_hash !== null;
    }

    /**
     * REGISTERED API SCOPES ARE CHECKED ON EVERY SAVE, not only in the registry.
     *
     * `scopes` is a free-text column, and hosts write it directly — a console that edits
     * an app's scopes sets the attribute and saves. A check in the registry alone would
     * guard the one door nobody uses for updates. So the rule runs where every writer
     * converges: a client may not be saved holding a registered scope its owner may not
     * hold.
     *
     * Only what CHANGES is judged. On an update that touches `scopes` alone, the scopes
     * being ADDED are checked — a client that legitimately held a free-text key before an
     * API registered it must still be editable (issuance drops the scope for it). A change
     * of owner, or becoming dynamically registered, re-judges everything it holds.
     *
     * The same hook set also keeps the secret store in step with a pre-1.19 host that still
     * writes `secret_hash` directly, and clears a deleted client's verifiers.
     */
    protected static function booted(): void
    {
        static::saving(static function (self $client): void {
            $held = $client->getAttribute('scopes');
            $scopes = is_array($held) ? array_values(array_filter($held, 'is_string')) : [];

            if ($client->exists && ! $client->isDirty(['organization_id', 'registration_access_token_hash'])) {
                if (! $client->isDirty('scopes')) {
                    return;
                }

                $original = $client->getOriginal('scopes');
                $scopes = array_values(array_diff($scopes, is_array($original) ? array_filter($original, 'is_string') : []));
            }

            if ($scopes === []) {
                return;
            }

            $refused = app(AudienceResolver::class)->ungrantable(ScopeHolder::of($client), $scopes);

            if ($refused !== []) {
                throw ScopeNotGrantable::forScopes($refused);
            }
        });

        // A pre-1.19 rotation: the host assigned `secret_hash` and saved. Adopted, so the
        // secret it wrote is the one that authenticates. The store writes this column with
        // a query, never a save, so its own writes never arrive here.
        static::saved(static function (self $client): void {
            $written = $client->wasRecentlyCreated
                ? $client->secret_hash !== null
                : $client->wasChanged('secret_hash');

            if ($written) {
                app(ClientSecretStore::class)->adoptLegacyHash($client);
            }
        });

        // The foreign key cascades on engines that enforce it; this covers the ones that do
        // not, so a deleted client never leaves a verifier behind.
        static::deleted(static function (self $client): void {
            StoredClientSecret::query()->where('oauth_client_id', $client->id)->delete();
        });
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => ClientType::class,
            'token_endpoint_auth_method' => TokenEndpointAuthMethod::class,
            'redirect_uris' => 'array',
            'post_logout_redirect_uris' => 'array',
            'grant_types' => 'array',
            'scopes' => 'array',
            'jwks' => 'array',
            'first_party' => 'boolean',
            'backchannel_logout_session_required' => 'boolean',
        ];
    }
}
