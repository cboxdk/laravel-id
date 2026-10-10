<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Pipes\PipeProviderCatalog;
use Cbox\Id\Pipes\ValueObjects\PipeProvider;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One environment's OAuth app at one third-party provider — the thing people connect
 * their own account through.
 *
 * The client secret is SEALED in `client_secret_encrypted` (SecretBox, AEAD-bound to this
 * row's id through {@see self::secretContext()}) and opened only to talk to the provider.
 * It is never part of {@see self::toArray()}: the attribute is hidden, so a host that
 * returns the model from a controller cannot leak it by accident.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $provider
 * @property string $client_id
 * @property string $client_secret_encrypted
 * @property list<string> $scopes
 * @property array<string, string>|null $parameters
 * @property bool $enabled
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class Pipe extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'pipes';

    protected $guarded = [];

    protected $hidden = ['client_secret_encrypted'];

    /** The AEAD context of the sealed client secret — tied to the immutable primary key. */
    public function secretContext(): string
    {
        return 'cbox-id:pipe-client-secret:'.$this->id;
    }

    /** The catalogue entry, or null for a provider since removed from the catalogue. */
    public function catalogueEntry(): ?PipeProvider
    {
        return PipeProviderCatalog::find($this->provider);
    }

    /** @return array<string, string> */
    public function parameterValues(): array
    {
        return $this->parameters ?? [];
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scopes' => 'array',
            'parameters' => 'array',
            'enabled' => 'boolean',
        ];
    }
}
