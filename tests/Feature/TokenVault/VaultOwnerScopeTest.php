<?php

declare(strict_types=1);

use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Exceptions\LeaseDenied;
use Cbox\Id\TokenVault\Exceptions\SecretNotFound;
use Cbox\Id\TokenVault\Models\VaultGrant;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * @group isolation
 *
 * The vault holds downstream credentials in plaintext-on-lease, so this is the one place
 * where a cross-tenant miss hands the attacker a working secret for a THIRD-PARTY system
 * rather than access within ours. Secrets are environment-scoped by the tenancy kernel,
 * but an environment holds many organizations — owner scope is the boundary that separates
 * two tenants' credentials.
 */
function orgBSecret(): string
{
    return app(SecretVault::class)->store(
        'github-token',
        'github',
        'ghp_org_b_real_secret',
        VaultOwner::organization('org-b'),
    )->id;
}

it('refuses to grant, lease, rotate or revoke another organization\'s secret', function (): void {
    $victim = orgBSecret();
    $vault = app(SecretVault::class);
    $attacker = VaultOwner::organization('org-a');

    // Every management path is closed…
    expect(fn () => $vault->grant($victim, 'attacker-agent', $attacker))->toThrow(SecretNotFound::class);
    expect(fn () => $vault->rotate($victim, 'ghp_hijacked', $attacker))->toThrow(SecretNotFound::class);

    // revoke() refuses the same way (a foreign id is indistinguishable from a missing one).
    expect(fn () => $vault->revoke($victim, $attacker))->toThrow(SecretNotFound::class);

    // revokeGrant() is idempotent by contract, so it silently does nothing — assert on STATE.
    $vault->revokeGrant($victim, 'attacker-agent', $attacker);

    // No grant was minted for the attacker's agent.
    expect(VaultGrant::query()->where('client_id', 'attacker-agent')->exists())->toBeFalse();

    // The secret is untouched and still leasable by its rightful owner — proving the
    // attacker's revoke() did not land.
    $owner = VaultOwner::organization('org-b');
    $vault->grant($victim, 'org-b-agent', $owner);

    expect($vault->lease($victim, 'org-b-agent', 'deploy', $owner)->secret)->toBe('ghp_org_b_real_secret');
});

it('never returns plaintext to a caller outside the owning organization', function (): void {
    $victim = orgBSecret();
    $vault = app(SecretVault::class);

    // Even WITH a live grant to the agent, leasing under the wrong owner scope fails —
    // so a stolen/borrowed grant is not enough to open the envelope.
    $vault->grant($victim, 'shared-agent', VaultOwner::organization('org-b'));

    expect(fn () => $vault->lease($victim, 'shared-agent', 'exfil', VaultOwner::organization('org-a')))
        ->toThrow(LeaseDenied::class);
});

it('keeps an unowned platform secret separate from an org-owned one', function (): void {
    $vault = app(SecretVault::class);
    $platform = $vault->store('smtp', 'postmark', 'pm_platform', null)->id;
    $org = $vault->store('smtp', 'postmark', 'pm_org_a', VaultOwner::organization('org-a'))->id;

    // A null owner addresses ONLY unowned rows — it is not a wildcard.
    expect(fn () => $vault->rotate($org, 'x', null))->toThrow(SecretNotFound::class);

    // …and an org scope cannot reach the platform's own secret.
    expect(fn () => $vault->rotate($platform, 'x', VaultOwner::organization('org-a')))
        ->toThrow(SecretNotFound::class);
});

/**
 * Uniqueness is per OWNER, not per environment. Env-wide uniqueness let one tenant squat
 * a name every other tenant wants, and the constraint violation itself reported that the
 * name was taken — an existence oracle across the tenant boundary.
 */
it('lets two organizations hold a secret of the same name', function (): void {
    $vault = app(SecretVault::class);

    $a = $vault->store('github-token', 'github', 'ghp_a', VaultOwner::organization('org-a'));
    $b = $vault->store('github-token', 'github', 'ghp_b', VaultOwner::organization('org-b'));

    expect($a->id)->not->toBe($b->id);

    // Each opens to its own value, not the other's.
    $vault->grant($a->id, 'agent', VaultOwner::organization('org-a'));
    $vault->grant($b->id, 'agent', VaultOwner::organization('org-b'));

    expect($vault->lease($a->id, 'agent', 'ci', VaultOwner::organization('org-a'))->secret)->toBe('ghp_a')
        ->and($vault->lease($b->id, 'agent', 'ci', VaultOwner::organization('org-b'))->secret)->toBe('ghp_b');
});
