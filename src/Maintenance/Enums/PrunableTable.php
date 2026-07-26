<?php

declare(strict_types=1);

namespace Cbox\Id\Maintenance\Enums;

use Cbox\Id\Maintenance\Pruner;
use Cbox\Id\Provisioning\Enums\OperationStatus;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * Every table in the platform that accumulates rows which stop being useful once
 * they are past their own expiry (or terminal), together with the exact predicate
 * that selects a dead row and the default number of days a dead row is kept.
 *
 * The predicate lives WITH the table rather than in the command, because "which rows
 * are safe to delete" is a property of what the table means, not of how the sweep is
 * driven — `events` may only lose DISPATCHED rows, `webhook_deliveries` only TERMINAL
 * ones, and a refresh token may only go once it could no longer be redeemed anyway.
 *
 * Deliberately ABSENT: `audit_logs`. See {@see Pruner} for why
 * pruning a hash-chained, checkpoint-anchored table would destroy the tamper-evidence
 * it exists to provide.
 *
 * Queries are built on the raw query builder, not Eloquent: the sweep is a
 * deliberately environment-SPANNING system operation (the same posture as the outbox
 * relay), so the hard environment scope must not narrow it to whichever environment
 * happened to be in context when the scheduler ticked.
 */
enum PrunableTable: string
{
    case DpopProofs = 'dpop_proofs';
    case ConsumedAssertions = 'consumed_assertions';
    case OauthAuthorizationCodes = 'oauth_authorization_codes';
    case OauthAccessTokens = 'oauth_access_tokens';
    case OauthRefreshTokens = 'oauth_refresh_tokens';
    case Events = 'events';
    case AuthSessions = 'auth_sessions';
    case UsageMeteredEvents = 'usage_metered_events';
    case WebhookDeliveries = 'webhook_deliveries';
    case ProvisioningOperations = 'provisioning_operations';

    /**
     * How long a dead row is kept by default, in days.
     *
     * Replay guards (`dpop_proofs`, `consumed_assertions`, authorization codes) are
     * worthless the moment the artefact they guard has expired, so they get the
     * shortest window — `dpop_proofs` in particular takes one INSERT per
     * DPoP-protected request, which is the fastest-growing table in the system.
     *
     * Everything an operator might reasonably want to look at after the fact
     * (sessions, deliveries, the outbox) keeps a month.
     */
    public function defaultRetentionDays(): int
    {
        return match ($this) {
            self::DpopProofs, self::ConsumedAssertions, self::OauthAuthorizationCodes => 1,
            self::OauthAccessTokens => 7,
            self::OauthRefreshTokens, self::Events, self::AuthSessions,
            self::UsageMeteredEvents, self::WebhookDeliveries, self::ProvisioningOperations => 30,
        };
    }

    /**
     * The primary key to chunk on. `DELETE ... LIMIT` is not portable to Postgres,
     * so the sweep selects a page of keys and deletes by key — which needs to know
     * what the key is called.
     */
    public function keyColumn(): string
    {
        return match ($this) {
            // A dedup marker keyed by the event id it meters; it has no surrogate id.
            self::UsageMeteredEvents => 'event_id',
            default => 'id',
        };
    }

    /**
     * Rows that are dead as of `$cutoff` — already past their usefulness AND older
     * than the configured retention window.
     */
    public function deadRows(Carbon $cutoff): Builder
    {
        $query = DB::table($this->value);

        return match ($this) {
            // Single-use replay guards: dead once their own freshness window closed.
            self::DpopProofs, self::ConsumedAssertions => $query->where('expires_at', '<', $cutoff),

            // An authorization code is one-shot and short-lived; expired or consumed,
            // it can never be exchanged again.
            self::OauthAuthorizationCodes => $query->where('expires_at', '<', $cutoff),

            // An expired access token introspects as inactive from its own expiry, so
            // the row past retention answers no question that its absence does not.
            self::OauthAccessTokens => $query->where('expires_at', '<', $cutoff),

            // Refresh-token reuse detection needs the consumed row to survive as long
            // as the token could still be presented — which is exactly until
            // `expires_at`. Past that, redemption is refused on expiry regardless.
            self::OauthRefreshTokens => $query->where('expires_at', '<', $cutoff),

            // The outbox may only lose TERMINAL rows: dispatched, or dead-lettered after
            // exhausting its delivery attempts. An undispatched row is undelivered work,
            // however old it is, and a claimed row belongs to a relay pass that may still
            // be running. A dead-lettered row is retained on the same clock as a delivered
            // one so an operator has the full retention window to find it — without it the
            // row would be immortal, since the relay never touches it again.
            self::Events => $query->where(fn (Builder $terminal) => $terminal
                ->where(fn (Builder $dispatched) => $dispatched
                    ->whereNotNull('dispatched_at')
                    ->where('dispatched_at', '<', $cutoff))
                ->orWhere(fn (Builder $dead) => $dead
                    ->whereNotNull('dead_lettered_at')
                    ->where('dead_lettered_at', '<', $cutoff))),

            // Expiry alone, deliberately — NOT `expires_at < ? OR revoked_at < ?`.
            // A revoked session keeps the `expires_at` it was created with, so it is
            // swept at most one session TTL later than an OR would manage, and a
            // single-column predicate can actually use the `expires_at` index where
            // an OR across two columns would degrade to a scan.
            self::AuthSessions => $query->where('expires_at', '<', $cutoff),

            // The exactly-once metering marker only has to outlive the redelivery
            // window of the event it deduplicates.
            self::UsageMeteredEvents => $query->where('created_at', '<', $cutoff),

            // TERMINAL deliveries only. A `failed` row is still owed a retry by
            // {@see \Cbox\Id\Webhooks\HttpWebhookDispatcher::retryPending()} — deleting
            // it would silently drop the webhook.
            self::WebhookDeliveries => $query
                ->whereIn('status', [DeliveryStatus::Delivered->value, DeliveryStatus::Exhausted->value])
                ->where('updated_at', '<', $cutoff),

            // Same rule for the provisioning outbox: `pending` and `failed` are live
            // work that {@see \Cbox\Id\Provisioning\OutboxProvisioningService} re-attempts.
            self::ProvisioningOperations => $query
                ->whereIn('status', [OperationStatus::Delivered->value, OperationStatus::Exhausted->value])
                ->where('updated_at', '<', $cutoff),
        };
    }
}
