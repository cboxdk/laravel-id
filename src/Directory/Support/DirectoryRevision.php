<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Support;

use Cbox\Id\Scim\Support\ScimETag;
use Illuminate\Database\Eloquent\Model;

/**
 * The revision counter behind a directory resource's entity-tag
 * ({@see ScimETag::forRevision()}).
 *
 * Called from each model's `saving` hook, which Eloquent fires BEFORE it decides
 * whether anything changed and before it touches `updated_at` — so `isDirty()` here
 * means "this save changes the stored resource", and an idempotent re-push (the same
 * attributes written again) keeps its tag, as it should: the representation did not
 * change.
 *
 * Not atomic across concurrent writers — two writers that read revision 4 both write 5.
 * That is the same window every read-modify-write in this store already has; the tag
 * makes a lost update detectable for a client that sends `If-Match`, it does not lock.
 */
class DirectoryRevision
{
    public static function advance(Model $model): void
    {
        $current = $model->getAttribute('version');
        $revision = is_numeric($current) ? (int) $current : 0;

        if (! $model->exists) {
            $model->setAttribute('version', max(1, $revision));

            return;
        }

        // A caller that set the revision itself (recordRevision()) has already moved it.
        if ($model->isDirty() && ! $model->isDirty('version')) {
            $model->setAttribute('version', $revision + 1);
        }
    }
}
