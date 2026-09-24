<?php

declare(strict_types=1);

namespace Cbox\Id\OAuthServer\Listeners;

use Cbox\Id\Kernel\Events\EventDelivered;
use Cbox\Id\OAuthServer\Contracts\RefreshTokens;
use Cbox\Id\Organization\MembershipService;

/**
 * When a person is removed from an organization, withdraw what they were granted in it:
 * the refresh tokens scoped to that organization, and — through
 * {@see RefreshTokens::withdrawAccess()} — the application sessions those grants signed
 * them in to (Back-Channel Logout).
 *
 * WITHOUT THIS, REMOVAL WAS INVISIBLE TO EVERY APP. The membership row went, the role
 * assignments went with it, and an application that had signed the person in to that
 * organization kept them signed in until its own session expired; one holding a refresh
 * token went on refreshing it. Consumers compensated by re-checking membership on every
 * request, which is the tax this listener removes.
 *
 * From the outbox, like every other reaction to a domain event here, so it runs once the
 * removal has committed, inside the event's own environment. Delivery is at-least-once;
 * a second pass revokes nothing and notifies nobody, because both halves are idempotent.
 */
class WithdrawAccessOnMembershipRemoval
{
    /**
     * `organization.member_removed` is what {@see MembershipService}
     * emits; `membership.deleted` is the catalogue name for the same fact.
     */
    public const EVENTS = ['organization.member_removed', 'membership.deleted'];

    public function __construct(private readonly RefreshTokens $refreshTokens) {}

    public function handle(EventDelivered $delivered): void
    {
        $event = $delivered->event;

        if (! in_array($event->type, self::EVENTS, true)) {
            return;
        }

        $userId = $event->payload['user_id'] ?? null;
        $organizationId = $event->organization_id;

        // Both, or nothing: an organization-less removal is not one this can scope, and
        // widening it to the whole subject would sign the person out of every org they
        // still belong to.
        if (! is_string($userId) || $userId === '' || ! is_string($organizationId) || $organizationId === '') {
            return;
        }

        $this->refreshTokens->withdrawAccess($userId, $organizationId);
    }
}
