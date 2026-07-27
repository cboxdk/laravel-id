<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Testing\FakeAuditLog;
use Cbox\Id\Platform\AccountProvisioner;
use Cbox\Id\Platform\Contracts\Accounts;
use Cbox\Id\Platform\Enums\AccountStatus;
use Cbox\Id\Platform\ValueObjects\AccountBlueprint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * Suspending an account is the widest access revocation the platform has — every
 * member, every key, every environment the account owns, all at once. It used to be
 * the only such verb that took no actor and wrote no audit entry: `Organizations` and
 * `PlatformOperators` both audit internally, `Accounts` did not, so the entry had to
 * be written at the call site and a second caller could silently forget it.
 */

/**
 * Fake the audit log FIRST, then provision.
 *
 * `Accounts` is a container singleton with the log constructor-injected, so faking
 * after something has already resolved it would leave the repository holding the real
 * log — and every assertion here would then pass or fail for the wrong reason.
 *
 * @return array{0: FakeAuditLog, 1: string} [fake log, account id]
 */
function anAuditedAccount(string $email = 'owner@suspend.test'): array
{
    /** @var FakeAuditLog $audit */
    $audit = test()->fakeAudit();

    $accountId = app(AccountProvisioner::class)->provision(new AccountBlueprint(
        accountName: 'Acme',
        ownerEmail: $email,
        ownerName: 'Owner',
        ownerPassword: 'supersecret123',
    ))->account->id;

    return [$audit, $accountId];
}

it('audits a suspension against the operator who performed it', function (): void {
    [$audit, $accountId] = anAuditedAccount();

    $accounts = app(Accounts::class);
    $accounts->suspend($accountId, 'op_42');

    expect($accounts->find($accountId)?->status)->toBe(AccountStatus::Suspended);

    $audit->assertRecorded('account.suspended', fn ($event): bool => $event->actorId === 'op_42'
        && $event->targetType === 'account'
        && $event->targetId === $accountId
        // The account sits above the tenancy boundary, so the entry belongs on
        // the SYSTEM chain, not a tenant's.
        && $event->organizationId === null);
});

it('audits a reactivation too, so a lifted suspension is not an untraceable act', function (): void {
    [$audit, $accountId] = anAuditedAccount();

    $accounts = app(Accounts::class);
    $accounts->suspend($accountId, 'op_42');
    $accounts->reactivate($accountId, 'op_7');

    expect($accounts->find($accountId)?->status)->toBe(AccountStatus::Active);

    $audit->assertRecorded('account.reactivated', fn ($event): bool => $event->actorId === 'op_7');
});

it('stays idempotent without appending a duplicate entry', function (): void {
    [$audit, $accountId] = anAuditedAccount();

    $accounts = app(Accounts::class);
    $accounts->suspend($accountId, 'op_42');

    $recordedAfterFirst = count($audit->recorded);

    // Both no-ops: already suspended, and an id that does not exist.
    $accounts->suspend($accountId, 'op_42');
    $accounts->suspend('acct_missing', 'op_42');

    expect($accounts->find($accountId)?->status)->toBe(AccountStatus::Suspended)
        ->and($audit->recorded)->toHaveCount($recordedAfterFirst);
});
