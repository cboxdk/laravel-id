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
        if (self::changes($model) && ! $model->isDirty('version')) {
            $model->setAttribute('version', $revision + 1);
        }
    }

    /**
     * Whether the save changes what is stored — by VALUE.
     *
     * `isDirty()` alone is not that on MySQL: its JSON column hands back the document with
     * its keys re-ordered, and Eloquent compares a decoded array-cast attribute with `===`,
     * which is order-sensitive — so writing the very same resource again looked like a
     * change there and nowhere else, and the tag moved on an idempotent re-push. A JSON
     * attribute whose old and new values are the same document, keys in any order, is
     * not a change.
     */
    private static function changes(Model $model): bool
    {
        foreach (array_keys($model->getDirty()) as $key) {
            $now = $model->getAttribute($key);
            $was = $model->getOriginal($key);

            if (! is_array($now) || ! is_array($was) || self::canonical($now) !== self::canonical($was)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  array<mixed>  $value
     * @return array<mixed>
     */
    private static function canonical(array $value): array
    {
        if (! array_is_list($value)) {
            ksort($value);
        }

        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = self::canonical($item);
            }
        }

        return $value;
    }
}
