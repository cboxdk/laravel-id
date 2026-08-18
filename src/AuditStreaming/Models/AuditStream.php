<?php

declare(strict_types=1);

namespace Cbox\Id\AuditStreaming\Models;

use Cbox\Id\Kernel\Tenancy\Concerns\BelongsToEnvironment;
use Cbox\Id\Kernel\Tenancy\Contracts\EnvironmentOwned;
use Cbox\Id\Kernel\Tenancy\Scopes\EnvironmentScope;
use Cbox\LaravelSiem\Models\LogStream;
use Illuminate\Database\Eloquent\Builder;

/**
 * An environment-owned {@see LogStream}. This is the one line that gives the whole
 * SIEM delivery engine its isolation for free: by pointing
 * `config('siem.models.log_stream')` at this subclass, EVERY read/list/create the
 * engine performs (registry, dispatcher, pump) flows through the hard
 * {@see EnvironmentScope} — deny-by-default, so a
 * query with no ambient environment matches zero rows, and a write is stamped and
 * fenced to the current environment.
 *
 * The base model is deliberately tenancy-agnostic (its `owner_key` seam is left
 * unused here); the `environment_id` column added by this package's migration is
 * the authoritative boundary. Casts, ULID keys and `$guarded = []` are inherited
 * from {@see LogStream}, so nothing about the engine's own schema is re-declared.
 *
 * @property string $environment_id
 * @property string|null $organization_id
 */
class AuditStream extends LogStream implements EnvironmentOwned
{
    use BelongsToEnvironment;

    /**
     * The streams an entry belonging to this organization may be delivered to.
     *
     * TWO KINDS, and the difference is the tenant boundary. A stream with an
     * `organization_id` is that organization's own: it receives that organization's
     * entries and nothing else, which is what makes log streaming safe to offer on the
     * organization plane at all. A stream with none is the ENVIRONMENT's, configurable
     * only from the environment plane, and receives everything — the operator's own
     * compliance shipping, which is what every stream was before organizations could
     * have one.
     *
     * An entry with no organization (a platform-level event) reaches only the
     * environment's streams, because there is no tenant it belongs to.
     *
     * @param  Builder<AuditStream>  $query
     * @return Builder<AuditStream>
     */
    public function scopeDeliverableFor($query, ?string $organizationId)
    {
        return $query->where(function ($q) use ($organizationId): void {
            $q->whereNull('organization_id');

            if ($organizationId !== null) {
                $q->orWhere('organization_id', $organizationId);
            }
        });
    }

    /**
     * The streams one organization OWNS — what its console may list, pause and delete.
     *
     * Deliberately not the same question as {@see scopeDeliverableFor()}: an organization
     * receives the environment's streams' attention and must never be able to manage
     * them. The difference between the two scopes IS the control.
     *
     * @param  Builder<AuditStream>  $query
     * @return Builder<AuditStream>
     */
    public function scopeOwnedByOrganization($query, ?string $organizationId)
    {
        return $organizationId === null
            ? $query->whereNull('organization_id')
            : $query->where('organization_id', $organizationId);
    }
}
