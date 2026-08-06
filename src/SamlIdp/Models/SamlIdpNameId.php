<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;

/**
 * One subject's pseudonym at one service provider.
 *
 * A Persistent NameID (SAML Core §8.3.7) is defined as opaque and SP-specific: stable
 * for that provider, and uncorrelatable with the value any other provider sees. Ours was
 * the person's email address at every provider, because the format was never consulted —
 * so the identifier was both PII and a perfect join key between any two SPs that
 * compared their user lists.
 *
 * Environment-owned, because an EntityID is not globally unique and a pseudonym only
 * means anything inside the environment that issued it.
 *
 * @property string $id
 * @property string $environment_id
 * @property string $sp_entity_id
 * @property string $subject_id
 * @property string $name_id
 */
class SamlIdpNameId extends Model implements EnvironmentOwned
{
    use BelongsToEnvironment;
    use HasUlids;

    protected $table = 'saml_idp_name_ids';

    protected $guarded = [];

    /**
     * The pseudonym this service provider knows this subject by, minting one on first
     * use.
     *
     * 128 bits from the CSPRNG, hex-encoded. Not derived from the subject id, the email,
     * or a keyed hash of either: a derived identifier is only as opaque as the secret
     * behind it stays, and re-keying one leaked provider would change every other
     * provider's identifiers at the same time.
     *
     * `firstOrCreate` on the unique key rather than a read-then-write, so two
     * simultaneous assertions for the same person cannot mint two pseudonyms and leave
     * the SP holding one the next assertion contradicts.
     */
    public static function pairwiseFor(string $spEntityId, string $subjectId): string
    {
        /** @var self $record */
        $record = self::query()->firstOrCreate(
            ['sp_entity_id' => $spEntityId, 'subject_id' => $subjectId],
            ['name_id' => bin2hex(random_bytes(16))],
        );

        return $record->name_id;
    }
}
