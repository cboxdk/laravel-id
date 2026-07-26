<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Exceptions\CrossEnvironmentAccess;
use Cbox\Id\Kernel\Tenancy\Testing\InteractsWithTenancy;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\InvalidInvitation;
use Cbox\Id\Organization\Models\Membership;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithTenancy::class);

it('creates a pending invitation without granting membership', function (): void {
    $org = $this->makeOrganization();

    $pending = app(Invitations::class)->invite($org->id, 'new@corp.com', 'member', invitedBy: 'admin_1');

    expect($pending->token)->toStartWith('inv_')
        ->and($pending->invitation->isPending())->toBeTrue()
        ->and(app(Invitations::class)->pending($org->id))->toHaveCount(1)
        // No membership until accepted.
        ->and(app(Memberships::class)->forOrganization($org->id))->toBeEmpty();
});

it('grants membership only when the invitee accepts', function (): void {
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);
    $pending = $invitations->invite($org->id, 'dana@corp.com', 'admin');

    $membership = $invitations->accept($pending->token, 'subject_dana');

    expect($membership->role->value)->toBe('admin')
        ->and(app(Memberships::class)->of($org->id, 'subject_dana')?->role?->value)->toBe('admin')
        ->and($invitations->pending($org->id))->toBeEmpty(); // no longer pending
});

it('rejects an unknown, reused, or revoked token', function (): void {
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);
    $pending = $invitations->invite($org->id, 'x@corp.com', 'member');

    $invitations->accept($pending->token, 'subject_x'); // first accept consumes it

    $invitations->accept($pending->token, 'subject_y'); // reuse -> invalid
})->throws(InvalidInvitation::class);

it('supersedes an earlier pending invite for the same email', function (): void {
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);

    $first = $invitations->invite($org->id, 'same@corp.com', 'member');
    $invitations->invite($org->id, 'same@corp.com', 'admin');

    expect($invitations->pending($org->id))->toHaveCount(1);

    // The superseded token no longer works.
    expect(fn () => $invitations->accept($first->token, 'subject_z'))->toThrow(InvalidInvitation::class);
});

it('revokes a pending invitation', function (): void {
    $org = $this->makeOrganization();
    $invitations = app(Invitations::class);
    $pending = $invitations->invite($org->id, 'gone@corp.com', 'member');

    $invitations->revoke($org->id, $pending->invitation->id);

    expect($invitations->pending($org->id))->toBeEmpty()
        ->and(fn () => $invitations->accept($pending->token, 's'))->toThrow(InvalidInvitation::class);
});

it('refuses to revoke an invitation from another organization (IDOR)', function (): void {
    $orgA = $this->makeOrganization('A');
    $orgB = $this->makeOrganization('B');
    $invitations = app(Invitations::class);
    $pending = $invitations->invite($orgA->id, 'x@corp.com', 'member');

    $invitations->revoke($orgB->id, $pending->invitation->id); // wrong org

    expect($invitations->pending($orgA->id))->toHaveCount(1); // untouched
});

/**
 * @group isolation
 */
it('refuses an invitation token redeemed in a DIFFERENT environment', function (): void {
    // `invitations` was the only credential-bearing table without an environment_id,
    // and byToken() matched on token_hash alone. That made the accept route a
    // cross-environment primitive: an attacker who self-serve signed up could invite
    // their OWN address in their OWN tenant, then hand-edit the emailed link's host to
    // a victim tenant. byToken() still found the row, findByEmail() (which IS
    // env-scoped) found nothing, so a new ACTIVE user was created in the victim
    // environment, a membership was stamped there, and a real session was established —
    // yielding an access token from the VICTIM's issuer.
    //
    // Note a plane gate would NOT have fixed this: the victim subdomain is a perfectly
    // valid subject-plane host. The token has to be bound to the environment that
    // issued it.
    $this->actingAsEnvironment('env_a');
    $org = $this->makeOrganization('Acme');
    $pending = app(Invitations::class)->invite($org->id, 'attacker@evil.test', 'member');

    // The attacker rewrites the host. Same token, different environment.
    $this->actingAsEnvironment('env_b');

    expect(app(Invitations::class)->byToken($pending->token))->toBeNull();
    expect(fn () => app(Invitations::class)->accept($pending->token, 'user_intruder'))
        ->toThrow(InvalidInvitation::class);

    // And nothing was written into the victim environment.
    expect(Membership::query()->count())->toBe(0);

    // The invitation is still perfectly valid on its OWN host.
    $this->actingAsEnvironment('env_a');
    expect(app(Invitations::class)->byToken($pending->token))->not->toBeNull();
});

/**
 * @group isolation
 */
it('refuses to add a member to an organization from another environment', function (): void {
    // Defence in depth for the same boundary. tenant->runAs() sets only the TENANT
    // dimension — it never touches the environment — and BelongsToEnvironment auto-fills
    // environment_id on a fresh INSERT (its CrossEnvironmentAccess guard fires on a
    // MISMATCH, never on an insert). There is also no foreign key on
    // memberships.organization_id. So without an explicit check, an org id from another
    // environment is taken on trust and produces a membership whose organization lives
    // in one environment and whose row lives in another.
    $this->actingAsEnvironment('env_a');
    $org = $this->makeOrganization('Acme');

    $this->actingAsEnvironment('env_b');

    expect(fn () => app(Memberships::class)->add($org->id, 'user_1', 'member'))
        ->toThrow(CrossEnvironmentAccess::class);

    expect(Membership::query()->count())->toBe(0);
});
