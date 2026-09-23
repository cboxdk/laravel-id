<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\AccessChecker;
use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Governance\Enums\AccessKind;
use Cbox\Id\Governance\Enums\PendingPolicy;
use Cbox\Id\Governance\Enums\ReviewDecision;
use Cbox\Id\Governance\Exceptions\CampaignClosed;
use Cbox\Id\Governance\Exceptions\UnknownCampaign;
use Cbox\Id\Governance\Models\CertificationItem;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

uses()->group('isolation');

/*
 * THE LARGEST GRANTS IN THE SYSTEM WERE THE ONLY ONES NEVER REVIEWED.
 *
 * A campaign belonged to one organization and snapshotted that organization's own rows,
 * so a role held environment-wide — a staff role across every customer — sat in no
 * organization and appeared in no campaign. A null organization now names the
 * environment's own review, as it names the environment plane on the Roles contract.
 */

it('reviews the environment-wide grants, and only those', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support', clientId: 'app_cadastre', tenantAssignable: false);
    $editor = $roles->define('acme', 'Editor');

    $roles->assignEverywhere('staff-1', $support->id);
    $roles->assign('acme', 'user-1', $editor->id);
    app(Memberships::class)->add('acme', 'user-1', MembershipRole::Member);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open(null, 'Staff review');
    $items = $reviews->itemsFor($campaign->id);

    expect($campaign->organization_id)->toBeNull()
        ->and($items)->toHaveCount(1)
        ->and($items[0]->access_type)->toBe(AccessKind::EnvironmentRole)
        ->and($items[0]->subject_id)->toBe('staff-1')
        ->and($items[0]->access_ref)->toBe($support->id)
        ->and($items[0]->organization_id)->toBeNull()
        ->and($items[0]->source)->toBe('manual');
});

/**
 * @group security
 *
 * The other direction: a tenant's reviewer must not see — let alone revoke — the vendor's
 * staff grants, even though those grants apply inside the tenant.
 */
it('keeps environment-wide grants out of an organization’s review', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support', tenantAssignable: false);
    $roles->assignEverywhere('staff-1', $support->id);
    app(Memberships::class)->add('acme', 'user-1', MembershipRole::Member);

    $campaign = app(AccessReviews::class)->open('acme', 'Q3');

    $kinds = array_map(static fn (CertificationItem $item): AccessKind => $item->access_type, app(AccessReviews::class)->itemsFor($campaign->id));

    expect($kinds)->toBe([AccessKind::Membership]);
})->group('security');

it('revokes the environment-wide grant itself when a reviewer revokes it', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support', clientId: 'app_cadastre', tenantAssignable: false);
    $roles->assignEverywhere('staff-1', $support->id);
    $roles->assignEverywhere('staff-2', $support->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open(null, 'Staff review');
    $items = collect($reviews->itemsFor($campaign->id))->keyBy(fn (CertificationItem $item): string => $item->subject_id);

    $reviews->certify($items['staff-1']->id, 'env-admin', null);
    $reviews->revoke($items['staff-2']->id, 'env-admin', null, 'moved team');
    $reviews->close($campaign->id, null);

    expect($roles->everywhereFor('staff-2'))->toBe([])
        ->and($roles->everywhereFor('staff-1'))->toBe([$support->id])
        // Gone from every organization at once, which is what revoking it means.
        ->and(app(AccessChecker::class)->forToken('staff-2', 'acme', 'app_cadastre')->roles)->toBe([]);

    $revoked = CertificationItem::query()->whereKey($items['staff-2']->id)->firstOrFail();
    expect($revoked->applied)->toBeTrue()
        ->and($revoked->decision)->toBe(ReviewDecision::Revoked);
});

it('auto-revokes an environment-wide grant left pending under the revoke policy', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support');
    $roles->assignEverywhere('staff-1', $support->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open(null, 'Staff review', pendingPolicy: PendingPolicy::Revoke);
    $reviews->close($campaign->id, null);

    expect($roles->everywhereFor('staff-1'))->toBe([]);
});

/**
 * @group security
 *
 * A tenant naming the environment's campaign by id is refused exactly like a foreign
 * tenant's campaign: closing it would strip staff grants across every customer.
 */
it('refuses a tenant closing or deciding the environment’s review', function (): void {
    $roles = app(Roles::class);
    $support = $roles->define(null, 'Support');
    $roles->assignEverywhere('staff-1', $support->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open(null, 'Staff review');
    $item = $reviews->itemsFor($campaign->id)[0];

    expect(fn () => $reviews->close($campaign->id, 'acme'))
        ->toThrow(UnknownCampaign::class, "No governance campaign [{$campaign->id}] in this environment.");
    expect(fn () => $reviews->revoke($item->id, 'tenant-admin', 'acme'))
        ->toThrow(CampaignClosed::class, "Governance campaign [{$campaign->id}] is closed.");

    expect($roles->everywhereFor('staff-1'))->toBe([$support->id]);
})->group('security');

/**
 * @group security
 *
 * And the environment plane does not reach into a tenant's campaign by passing null: null
 * matches a null organization only, never "any".
 */
it('refuses the environment plane closing an organization’s review', function (): void {
    $roles = app(Roles::class);
    $editor = $roles->define('acme', 'Editor');
    $roles->assign('acme', 'user-1', $editor->id);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'Q3');

    expect(fn () => $reviews->close($campaign->id, null))
        ->toThrow(UnknownCampaign::class, "No governance campaign [{$campaign->id}] in this environment.");

    expect($roles->assignmentsForSubject('acme', 'user-1'))->toBe([$editor->id]);
})->group('security');

/**
 * @group security
 *
 * The item fence holds for the environment's campaign too: an organization's item
 * pointed at it (however the row came to exist) is never read — nor revoked — through it.
 */
it('never reads an organization’s item through the environment’s campaign', function (): void {
    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open(null, 'Staff review');

    CertificationItem::query()->create([
        'campaign_id' => $campaign->id,
        'access_type' => AccessKind::Membership,
        'subject_id' => 'user-1',
        'access_ref' => 'owner',
        'organization_id' => 'acme',
        'decision' => ReviewDecision::Revoked,
        'applied' => false,
    ]);

    expect($reviews->itemsFor($campaign->id))->toBe([])
        ->and($reviews->countItemsFor($campaign->id))->toBe(0);
})->group('security');
