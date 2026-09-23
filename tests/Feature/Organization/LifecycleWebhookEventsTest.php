<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\InvitationStatus;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Exceptions\SlugAlreadyTaken;
use Cbox\Id\Organization\ValueObjects\OrganizationChanges;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The tenancy lifecycle announces itself under the catalogued `membership.*`,
 * `invitation.*` and `organization.*` names — and every name asserted here is a case in
 * {@see WebhookEventType}, so the catalogue cannot offer an event the framework does not
 * emit, nor emit one the catalogue does not describe.
 */

// ---------------------------------------------------------------- membership.*

it('announces a new membership as membership.created', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();

    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Developer, invitedBy: 'alice');

    $events->assertEmitted(WebhookEventType::MembershipCreated->value, fn (DomainEvent $e): bool => $e->organizationId === $org->id
        && $e->payload === [
            'organization_id' => $org->id,
            'user_id' => 'bob',
            'role' => 'developer',
            'status' => 'active',
            'invited_by' => 'alice',
        ]);
});

it('does not announce a membership that already existed', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Member);
    $events->emitted = [];

    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Member);

    $events->assertNotEmitted(WebhookEventType::MembershipCreated->value);
});

it('announces a role change with the previous role, and a no-op change not at all', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Member);

    app(Memberships::class)->changeRole($org->id, 'bob', MembershipRole::Admin);

    $events->assertEmitted(WebhookEventType::MembershipUpdated->value, fn (DomainEvent $e): bool => $e->payload['role'] === 'admin'
        && $e->payload['previous_role'] === 'member'
        && $e->payload['reason'] === 'role_changed');

    $events->emitted = [];
    app(Memberships::class)->changeRole($org->id, 'bob', MembershipRole::Admin);

    $events->assertNotEmitted(WebhookEventType::MembershipUpdated->value);
});

it('announces a removal as membership.deleted with the role the member had', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    app(Memberships::class)->add($org->id, 'bob', MembershipRole::Viewer);

    app(Memberships::class)->remove($org->id, 'bob');

    $events->assertEmitted(WebhookEventType::MembershipDeleted->value, fn (DomainEvent $e): bool => $e->payload['role'] === 'viewer'
        && $e->payload['reason'] === 'removed');
});

// ---------------------------------------------------------------- invitation.*

it('announces an invitation, its acceptance, and a revocation', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);

    $pending = $invitations->invite($org->id, 'new@corp.test', MembershipRole::Member, invitedBy: 'alice');

    $events->assertEmitted(WebhookEventType::InvitationCreated->value, fn (DomainEvent $e): bool => $e->payload['invitation_id'] === $pending->invitation->id
        && $e->payload['email'] === 'new@corp.test'
        && $e->payload['role'] === 'member'
        && $e->payload['invited_by'] === 'alice');

    $invitations->accept($pending->token, 'bob');

    $events->assertEmitted(WebhookEventType::InvitationAccepted->value, fn (DomainEvent $e): bool => $e->payload['invitation_id'] === $pending->invitation->id
        && $e->payload['user_id'] === 'bob');

    $second = $invitations->invite($org->id, 'other@corp.test', MembershipRole::Viewer);
    $invitations->revoke($org->id, $second->invitation->id, revokedBy: 'alice');

    $events->assertEmitted(WebhookEventType::InvitationRevoked->value, fn (DomainEvent $e): bool => $e->payload['invitation_id'] === $second->invitation->id
        && $e->payload['reason'] === 'revoked');
    $audit->assertRecorded('organization.invitation_revoked', fn (AuditEvent $e): bool => $e->actorType === ActorType::User && $e->actorId === 'alice');
    expect($invitations->pending($org->id))->toHaveCount(0);
});

it('announces the invitation a re-invite supersedes as revoked', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);

    $first = $invitations->invite($org->id, 'new@corp.test', MembershipRole::Member);
    $invitations->invite($org->id, 'new@corp.test', MembershipRole::Admin);

    $events->assertEmitted(WebhookEventType::InvitationRevoked->value, fn (DomainEvent $e): bool => $e->payload['invitation_id'] === $first->invitation->id
        && $e->payload['reason'] === 'superseded');
    expect($invitations->byToken($first->token)?->status)->toBe(InvitationStatus::Revoked);
});

it('does not revoke another organization\'s invitation, nor announce anything for it', function (): void {
    $events = $this->fakeEvents();
    $mine = $this->makeOrganization('Mine');
    $theirs = $this->makeOrganization('Theirs');
    $pending = app(Invitations::class)->invite($theirs->id, 'x@corp.test', MembershipRole::Member);
    $events->emitted = [];

    app(Invitations::class)->revoke($mine->id, $pending->invitation->id);

    $events->assertNothingEmitted();
    expect(app(Invitations::class)->byToken($pending->token)?->isPending())->toBeTrue();
});

// ---------------------------------------------------------------- organization.*

it('renames an organization and announces organization.updated', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization('Acme');

    $updated = app(Organizations::class)->update($org->id, new OrganizationChanges(name: 'Acme Group'), actorId: 'alice');

    expect($updated->name)->toBe('Acme Group')
        ->and($updated->slug)->toBe($org->slug);
    $events->assertEmitted(WebhookEventType::OrganizationUpdated->value, fn (DomainEvent $e): bool => $e->payload['changed'] === ['name']
        && $e->payload['name'] === 'Acme Group');
    $audit->assertRecorded('organization.updated', fn (AuditEvent $e): bool => $e->actorId === 'alice');
});

it('writes and announces nothing for an update that changes nothing', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization('Acme');
    $events->emitted = [];

    app(Organizations::class)->update($org->id, new OrganizationChanges(name: 'Acme', slug: $org->slug));
    app(Organizations::class)->update($org->id, new OrganizationChanges);

    $events->assertNothingEmitted();
});

it('refuses a slug another organization holds', function (): void {
    $taken = $this->makeOrganization('Taken');
    $org = $this->makeOrganization('Acme');

    expect(fn () => app(Organizations::class)->update($org->id, new OrganizationChanges(slug: $taken->slug)))
        ->toThrow(SlugAlreadyTaken::class, $taken->slug);
});

it('announces a settings change as organization.updated', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();

    app(Organizations::class)->updateSettings($org->id, ['brand_color' => '#123456']);

    $events->assertEmitted(WebhookEventType::OrganizationUpdated->value, fn (DomainEvent $e): bool => $e->payload['changed'] === ['settings']
        && $e->payload['settings_keys'] === ['brand_color']);
});

it('announces an archive as organization.deleted, beside the legacy organization.archived', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();

    app(Organizations::class)->archive($org->id, 'operator_1');

    $events->assertEmitted(WebhookEventType::OrganizationDeleted->value, fn (DomainEvent $e): bool => $e->payload['id'] === $org->id
        && $e->payload['status'] === 'deleted');
    $events->assertEmitted(WebhookEventType::OrganizationArchived->value);
});

it('does not announce organization.deleted for a suspension', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization();

    app(Organizations::class)->suspend($org->id, 'operator_1');

    $events->assertNotEmitted(WebhookEventType::OrganizationDeleted->value);
});
