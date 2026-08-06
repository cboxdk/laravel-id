<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * One assertion we issued: which subject, to which service provider, under what NameID.
 *
 * Single Logout needs this and had nothing. It took the NameID out of a signed
 * LogoutRequest, resolved it as a subject id or an email, and revoked every session that
 * person had — so any registered SP could name any user (an email is not a secret) and
 * end their day, repeatedly, over users it had never seen.
 *
 * Environment-owned, because a NameID is only meaningful inside the environment that
 * issued it and an SP EntityID is not globally unique.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $sp_entity_id
 * @property string $subject_id
 * @property string $name_id
 * @property string $session_index
 * @property string $lookup_hash
 * @property Carbon|null $expires_at
 */
class SamlIdpSession extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_idp_sessions';

    protected $guarded = [];

    /**
     * Keep the lookup key in step with the two values it covers.
     *
     * The SLO query is an exact match on a pair the protocol does not bound: an SP
     * EntityID and a NameID are both URI-shaped and both stored at 512 characters. An
     * index over the raw pair is 4200 bytes in utf8mb4 and InnoDB stops at 3072, so the
     * table could not be created on MySQL or MariaDB at all — the digest is what makes
     * the lookup indexable on every engine we support, at 64 characters flat.
     *
     * Computed here rather than at the call site so a future writer cannot produce a row
     * that the logout path is unable to find: a missing hash is not a failed write, it is
     * a session that silently cannot be logged out.
     */
    protected static function booted(): void
    {
        static::saving(function (self $session): void {
            $session->lookup_hash = self::lookupHash(
                (string) $session->sp_entity_id,
                (string) $session->name_id,
            );
        });
    }

    /**
     * The indexed form of "this NameID, as issued to this service provider".
     *
     * NUL-separated because concatenation alone is ambiguous: without a separator that
     * cannot occur in either value, ('ab', 'c') and ('a', 'bc') hash the same, and an SP
     * choosing its own EntityID could aim its LogoutRequest at another SP's session.
     */
    public static function lookupHash(string $spEntityId, string $nameId): string
    {
        return hash('sha256', $spEntityId."\0".$nameId);
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return ['expires_at' => 'datetime'];
    }
}
