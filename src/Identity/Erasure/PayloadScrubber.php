<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Erasure;

use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;

/**
 * Rewrites a stored JSON payload (an outbox event, a webhook delivery, a queued SCIM
 * operation) so it no longer carries the erased subject's email or name.
 *
 * Exact-value replacement, recursively: a string equal to the subject's email (case
 * insensitive) becomes the placeholder email, and one equal to their name becomes the
 * placeholder name. Keys and every other value are left as they were, so the payload
 * keeps its shape and its non-personal meaning ("a member was added to org X").
 *
 * The name is replaced only in payloads that are ABOUT this subject (they mention the
 * id or the email). "Alice" in somebody else's event is somebody else's name.
 */
class PayloadScrubber
{
    /**
     * @template TKey of array-key
     *
     * @param  array<TKey, mixed>  $payload
     * @return array<TKey, mixed>|null the scrubbed payload, or null when nothing changed
     */
    public static function scrub(array $payload, ErasureRequest $request): ?array
    {
        $aboutSubject = self::mentions($payload, $request->subjectId) || ($request->email !== null && self::mentions($payload, $request->email));

        if (! $aboutSubject) {
            return null;
        }

        $changed = false;
        $scrubbed = self::walk($payload, $request, $changed);

        return $changed ? $scrubbed : null;
    }

    /**
     * Narrow a query to the rows whose JSON `payload` column mentions the subject's id or
     * email — a cheap pre-filter; {@see scrub()} decides on each candidate.
     *
     * The column is cast to text per driver because a JSON column does not take LIKE
     * portably: PostgreSQL has no `json ~~ text` operator at all, and MySQL compares a JSON
     * value under a binary collation. Lower-cased on both sides, since an address may have
     * been written with different capitalisation than the subject row now holds.
     *
     * @template TModel of Model
     *
     * @param  EloquentBuilder<TModel>  $query
     * @return EloquentBuilder<TModel>
     */
    public static function mentioningInPayload(EloquentBuilder $query, ErasureRequest $request): EloquentBuilder
    {
        $condition = match ($query->getModel()->getConnection()->getDriverName()) {
            'pgsql' => 'LOWER(CAST(payload AS TEXT)) LIKE ?',
            'mysql', 'mariadb' => 'LOWER(CAST(payload AS CHAR)) LIKE ?',
            'sqlsrv' => 'LOWER(CAST(payload AS NVARCHAR(MAX))) LIKE ?',
            default => 'LOWER(payload) LIKE ?',
        };

        $needles = array_values(array_filter([$request->subjectId, $request->email], static fn (?string $value): bool => $value !== null && $value !== ''));

        return $query->where(static function (EloquentBuilder $inner) use ($needles, $condition): void {
            foreach ($needles as $needle) {
                $inner->orWhereRaw($condition, ['%'.mb_strtolower($needle).'%']);
            }
        });
    }

    /**
     * @template TKey of array-key
     *
     * @param  array<TKey, mixed>  $data
     * @return array<TKey, mixed>
     */
    private static function walk(array $data, ErasureRequest $request, bool &$changed): array
    {
        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = self::walk($value, $request, $changed);

                continue;
            }

            if (! is_string($value)) {
                continue;
            }

            if ($request->email !== null && strcasecmp($value, $request->email) === 0) {
                $data[$key] = $request->pseudonym->email;
                $changed = true;
            } elseif ($request->name !== null && $request->name !== '' && $value === $request->name) {
                $data[$key] = $request->pseudonym->name;
                $changed = true;
            }
        }

        return $data;
    }

    /** @param  array<array-key, mixed>  $data */
    private static function mentions(array $data, string $needle): bool
    {
        foreach ($data as $value) {
            if (is_array($value) ? self::mentions($value, $needle) : (is_string($value) && strcasecmp($value, $needle) === 0)) {
                return true;
            }
        }

        return false;
    }
}
