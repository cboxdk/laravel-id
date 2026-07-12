<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Models;

use Cbox\Id\OAuthServer\Enums\ClientType;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * An OAuth client (relying party). `organization_id` null = a first-party client.
 * The secret is stored only as a SHA-256 hash.
 *
 * @property string $id
 * @property string|null $organization_id
 * @property string $client_id
 * @property string|null $secret_hash
 * @property string $name
 * @property ClientType $type
 * @property array<int, string> $redirect_uris
 * @property array<int, string> $grant_types
 * @property array<int, string> $scopes
 * @property bool $first_party
 * @property string|null $registration_access_token_hash
 * @property Carbon|null $created_at
 */
final class Client extends Model
{
    use HasUlids;

    protected $table = 'oauth_clients';

    protected $guarded = [];

    public function allows(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'type' => ClientType::class,
            'redirect_uris' => 'array',
            'grant_types' => 'array',
            'scopes' => 'array',
            'first_party' => 'boolean',
        ];
    }
}
