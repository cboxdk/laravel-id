<?php

declare(strict_types=1);

use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Exceptions\InvalidInvitation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

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

    expect($membership->role)->toBe('admin')
        ->and(app(Memberships::class)->of($org->id, 'subject_dana')?->role)->toBe('admin')
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
