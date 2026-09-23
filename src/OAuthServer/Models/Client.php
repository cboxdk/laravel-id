<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\OAuthServer\Contracts\AudienceResolver;
use Cbox\Id\OAuthServer\Enums\ClientType;
use Cbox\Id\OAuthServer\Enums\TokenEndpointAuthMethod;
use Cbox\Id\OAuthServer\Exceptions\ScopeNotGrantable;
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
 * The secret is stored only as a SHA-256 hash.
 *
 * @property string $id
 * @property string $environment_id
 * @property string|null $organization_id
 * @property string $client_id
 * @property string|null $secret_hash
 * @property array<string, mixed>|null $jwks
 * @property string $name
 * @property ClientType $type
 * @property TokenEndpointAuthMethod|null $token_endpoint_auth_method
 * @property array<int, string> $redirect_uris
 * @property array<int, string>|null $post_logout_redirect_uris
 * @property array<int, string> $grant_types
 * @property array<int, string> $scopes
 * @property string|null $manifest_url
 * @property int|null $access_token_ttl
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
        ];
    }
}
