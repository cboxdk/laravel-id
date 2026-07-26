<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Str;

/**
 * A SCIM resource synced from the customer's directory, linked to a local user.
 *
 * The SCIM payload lives in the `resource` JSON blob, but the two attributes RFC 7643
 * defines as `caseExact: false` — `userName` and the primary email — are ALSO kept in
 * their own lower-cased columns. See {@see normalize()} for why.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $directory_id
 * @property string $external_id
 * @property array<string, mixed> $resource
 * @property string|null $user_name_lower
 * @property string|null $email_lower
 * @property string|null $user_id
 * @property bool $active
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class DirectoryUser extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'directory_users';

    protected $guarded = [];

    /**
     * Fold a case-insensitive SCIM identifier (`userName`, email) to its comparison
     * form. Null for an absent or blank value, so `pr` and uniqueness both behave.
     *
     * RFC 7643 defines both attributes as `caseExact: false`, and ServiceProviderConfig
     * advertises `userName` as `uniqueness: "server"`. Matching them with the database's
     * default collation honoured neither: on PostgreSQL (case-SENSITIVE by default) an
     * IdP's pre-provision check for `Dana.Rivera@corp.com` found nothing, the create-side
     * collision check missed too, and a SECOND directory row plus a second subject were
     * minted for one human. On MySQL's `_ci` collations the same code looked correct, so
     * the bug was invisible until a Postgres deployment.
     */
    public static function normalize(?string $value): ?string
    {
        $value = $value === null ? '' : trim($value);

        return $value === '' ? null : Str::lower($value);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'resource' => 'array',
            'active' => 'boolean',
        ];
    }

    protected static function booted(): void
    {
        // Derive the comparison columns from the resource on EVERY write path — SCIM
        // push, API pull, console, backfill. A caller's responsibility is the wrong
        // place for this: the one writer that forgets mints the duplicate account the
        // columns exist to prevent.
        static::saving(static function (self $model): void {
            if (! array_key_exists('resource', $model->getAttributes())) {
                return;
            }

            $resource = $model->resource;

            $model->setAttribute('user_name_lower', self::normalize(self::stringOrNull($resource['userName'] ?? null)));
            $model->setAttribute('email_lower', self::normalize(self::stringOrNull($resource['email'] ?? null)));
        });
    }

    private static function stringOrNull(mixed $value): ?string
    {
        return is_string($value) ? $value : null;
    }
}
