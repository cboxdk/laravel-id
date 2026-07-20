<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Enums\ReviewDecision;
use Cbox\Id\Governance\Exceptions\CampaignClosed;
use Cbox\Id\Governance\Exceptions\UnknownCampaign;
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

    $reviews->certify($items['keep-user']->id, 'reviewer-1', 'acme');
    $reviews->revoke($items['revoke-user']->id, 'reviewer-1', 'acme', 'left the team');
    $reviews->close($campaign->id, 'acme');

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
    $reviews->revoke($item->id, 'reviewer-1', 'acme');
    $reviews->close($campaign->id, 'acme');

    expect(app(Memberships::class)->of('acme', 'member-1'))->toBeNull();
});

it('auto-revokes items left pending under the default (revoke) policy', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review'); // default PendingPolicy::Revoke
    $reviews->close($campaign->id, 'acme');               // nobody reviewed the item

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toBe([]);
});

it('keeps pending items when the policy is certify', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review', null, PendingPolicy::Certify);
    $reviews->close($campaign->id, 'acme');

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toHaveCount(1);
});

it('records a blocked revoke when removing the last owner (never silently dropped)', function (): void {
    app(Memberships::class)->add('acme', 'owner-1', 'owner');

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $item = $reviews->itemsFor($campaign->id)[0];
    $reviews->revoke($item->id, 'reviewer-1', 'acme');
    $reviews->close($campaign->id, 'acme');

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
    $reviews->close($campaign->id, 'acme');

    $reviews->certify($item->id, 'reviewer-1', 'acme');
})->throws(CampaignClosed::class);

it('is idempotent on re-close (never re-applies)', function (): void {
    $role = app(Roles::class)->define('acme', 'admin');
    app(Roles::class)->assign('acme', 'user-1', $role->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'review');
    $reviews->close($campaign->id, 'acme');
    // Re-assign after close, then re-close — the second close must not touch it.
    app(Roles::class)->assign('acme', 'user-1', $role->id);
    $reviews->close($campaign->id, 'acme');

    expect(app(Roles::class)->assignmentsForSubject('acme', 'user-1'))->toHaveCount(1);
});

/**
 * @group isolation
 *
 * Two orgs, one environment — so the environment scope cannot separate them. Closing a
 * campaign APPLIES every revoke against real memberships and roles, which makes a
 * foreign campaign id a cross-tenant access-stripping primitive. The console lists only
 * your own campaigns, but the id also travels in the governance.campaign_opened domain
 * event to environment webhooks, so list-scoping was never the control.
 */
it('refuses to certify, revoke or close another organization\'s campaign', function (): void {
    $reviews = app(AccessReviews::class);

    // Org B's campaign, covering a membership org B depends on.
    $role = app(Roles::class)->define('org-b', 'admin');
    app(Roles::class)->assign('org-b', 'victim-user', $role->id);
    app(Memberships::class)->add('org-b', 'victim-user', 'member');
    $victimCampaign = $reviews->open('org-b', 'Org B review');
    $victimItem = $reviews->itemsFor($victimCampaign->id)[0];

    // Org A's admin acts with org A as their scope.
    expect(fn () => $reviews->close($victimCampaign->id, 'org-a'))
        ->toThrow(UnknownCampaign::class)
        ->and(fn () => $reviews->certify($victimItem->id, 'attacker', 'org-a'))
        ->toThrow(CampaignClosed::class)
        ->and(fn () => $reviews->revoke($victimItem->id, 'attacker', 'org-a'))
        ->toThrow(CampaignClosed::class);

    // Nothing was decided, nothing was closed, and org B's access is intact.
    $victimCampaign->refresh();
    expect($victimCampaign->isClosed())->toBeFalse()
        ->and($reviews->itemsFor($victimCampaign->id)[0]->decision)->toBe($victimItem->decision)
        ->and(app(Memberships::class)->forOrganization('org-b'))->toHaveCount(1);

    // Org B's own admin still can.
    expect($reviews->close($victimCampaign->id, 'org-b')->isClosed())->toBeTrue();
});
