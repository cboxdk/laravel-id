<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Enums\ReviewDecision;
use Cbox\Id\Governance\Exceptions\CampaignClosed;
use Cbox\Id\Governance\Models\CertificationItem;
use Cbox\Id\Organization\Contracts\Memberships;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('snapshots roles and memberships as pending items', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);
    app(Memberships::class)->add('acme', 'user-2', 'member');

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'Q3 review');
    $items = collect($reviews->itemsFor($campaign->id))->keyBy(fn (CertificationItem $i): string => $i->access_type->value);

    expect($items)->toHaveCount(2)
        ->and($items['role']->subject_id)->toBe('user-1')
        ->and($items['role']->access_ref)->toBe($role->id)
        ->and($items['role']->decision)->toBe(ReviewDecision::Pending)
        ->and($items['membership']->subject_id)->toBe('user-2')
        ->and($items['membership']->access_ref)->toBe('member');
});

it('applies revoked decisions on close and leaves certified access intact', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'keep-user', $role->id);
    app(Roles::class)->assign('acme', 'revoke-user', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $items = collect($reviews->itemsFor($campaign->id))->keyBy(fn (CertificationItem $i): string => $i->subject_id);

    $reviews->certify($items['keep-user']->id, 'reviewer-1');
    $reviews->revoke($items['revoke-user']->id, 'reviewer-1', 'left the team');
    $reviews->close($campaign->id);

    expect(app(Roles::class)->assignmentsForSubject('acme', 'revoke-user'))->toBe([])
        ->and(app(Roles::class)->assignmentsForSubject('acme', 'keep-user'))->toHaveCount(1);

    $revoked = CertificationItem::query()->whereKey($items['revoke-user']->id)->firstOrFail();
    expect($revoked->applied)->toBeTrue()
        ->and($revoked->decision)->toBe(ReviewDecision::Revoked);
});

it('removes a revoked membership on close', function (): void {
    app(Memberships::class)->add('acme', 'member-1', 'member');

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $item = $reviews->itemsFor($campaign->id)[0];
    $reviews->revoke($item->id, 'reviewer-1');
    $reviews->close($campaign->id);

    expect(app(Memberships::class)->of('acme', 'member-1'))->toBeNull();
});

it('auto-revokes items left pending under the default (revoke) policy', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review'); // default PendingPolicy::Revoke
    $reviews->close($campaign->id);               // nobody reviewed the item

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toBe([]);
});

it('keeps pending items when the policy is certify', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review', null, PendingPolicy::Certify);
    $reviews->close($campaign->id);

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toHaveCount(1);
});

it('records a blocked revoke when removing the last owner (never silently dropped)', function (): void {
    app(Memberships::class)->add('acme', 'owner-1', 'owner');

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $item = $reviews->itemsFor($campaign->id)[0];
    $reviews->revoke($item->id, 'reviewer-1');
    $reviews->close($campaign->id);

    $settled = CertificationItem::query()->whereKey($item->id)->firstOrFail();
    expect($settled->applied)->toBeFalse()
        ->and($settled->application_note)->toContain('blocked');

    // The domain guard held — the sole owner still has their membership.
    expect(app(Memberships::class)->of('acme', 'owner-1'))->not->toBeNull();
});

it('refuses a decision on a closed campaign', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $item = $reviews->itemsFor($campaign->id)[0];
    $reviews->close($campaign->id);

    $reviews->certify($item->id, 'reviewer-1');
})->throws(CampaignClosed::class);

it('is idempotent on re-close (never re-applies)', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $reviews->close($campaign->id);
    // Re-assign after close, then re-close — the second close must not touch it.
    app(Roles::class)->assign('acme', 'user-1', $role->id);
    $reviews->close($campaign->id);

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toHaveCount(1);
});
