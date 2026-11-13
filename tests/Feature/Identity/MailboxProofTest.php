<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\MagicLink;
use Cbox\Id\Identity\Contracts\MailboxProof;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SubjectGrantRevoker;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\IdentityLink;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\MfaRecoveryCode;
use Cbox\Id\Identity\Models\PasswordResetToken;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\FederatedPrincipal;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Organization\Contracts\Invitations;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Contracts\UserApiTokens;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Enums\TokenScope;
use Cbox\Id\Organization\Models\Organization;
use Cbox\Id\Organization\Models\UserApiToken;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/*
 * An account registered under an address nobody confirmed is handed to whoever proves
 * the mailbox — by redeeming a sign-in link or accepting a mailed invitation — with
 * everything set on it before the proof withdrawn. A verified account is left alone.
 */

final class RecordingGrantRevoker implements SubjectGrantRevoker
{
    /** @var list<string> */
    public array $revoked = [];

    public function revokeGrantsForUser(string $userId): void
    {
        $this->revoked[] = $userId;
    }
}

beforeEach(function (): void {
    $this->grants = new RecordingGrantRevoker;
    app()->instance(SubjectGrantRevoker::class, $this->grants);
});

function mailboxOrg(): Organization
{
    return app(Organizations::class)->create(new NewOrganization(name: 'Acme', slug: 'acme-'.Str::lower(Str::random(6))));
}

/**
 * An account with something in every credential store, plus a live session and a
 * personal API token. Returns [subject id, earlier session id, api token id].
 *
 * @return array{0: string, 1: string, 2: string}
 */
function credentialedAccount(string $email, bool $verified): array
{
    $subjects = app(Subjects::class);
    $subject = $subjects->create($email, 'Account', 'an-unbreached-strong-passphrase');
    User::query()->whereKey($subject->id)->update(['email_verified_at' => $verified ? now() : null]);

    app(Mfa::class)->enrollTotp($subject->id, $email);
    app(Mfa::class)->generateRecoveryCodes($subject->id, 4);
    WebAuthnCredential::query()->create(['user_id' => $subject->id, 'credential_id' => 'cred-'.$subject->id, 'public_key' => 'pk', 'sign_count' => 0]);
    $subjects->link($subject->id, new FederatedPrincipal('github', 'gh-'.$subject->id, $email));
    PasswordResetToken::query()->create(['email' => $email, 'token_hash' => hash('sha256', 'reset-'.$email), 'expires_at' => now()->addHour()]);

    $session = app(SessionManager::class)->start($subject->id, null, ['pwd']);

    $org = mailboxOrg();
    app(Memberships::class)->add($org->id, $subject->id, MembershipRole::Owner);
    $token = app(UserApiTokens::class)->issue($org->id, $subject->id, 'CLI', TokenScope::Read);

    return [$subject->id, $session->id, $token->token->id];
}

function expectClaimed(string $id, string $earlierSession, string $tokenId, RecordingGrantRevoker $grants): void
{
    expect(app(Subjects::class)->find($id)?->emailVerified)->toBeTrue()
        ->and(app(Subjects::class)->verifyPassword($id, 'an-unbreached-strong-passphrase'))->toBeFalse()
        ->and(MfaFactor::query()->where('user_id', $id)->count())->toBe(0)
        ->and(MfaRecoveryCode::query()->where('user_id', $id)->count())->toBe(0)
        ->and(WebAuthnCredential::query()->where('user_id', $id)->count())->toBe(0)
        ->and(IdentityLink::query()->where('user_id', $id)->count())->toBe(0)
        ->and(PasswordResetToken::query()->count())->toBe(0)
        ->and(app(SessionManager::class)->active($earlierSession))->toBeNull()
        ->and(UserApiToken::query()->withoutGlobalScopes()->whereKey($tokenId)->value('revoked_at'))->not->toBeNull()
        ->and($grants->revoked)->toBe([$id])
        ->and(AuditEntry::query()->where('action', 'user.unverified_account_claimed')->where('target_id', $id)->exists())->toBeTrue();
}

function expectUntouched(string $id, string $earlierSession, string $tokenId, RecordingGrantRevoker $grants): void
{
    expect(app(Subjects::class)->verifyPassword($id, 'an-unbreached-strong-passphrase'))->toBeTrue()
        ->and(MfaFactor::query()->where('user_id', $id)->count())->toBeGreaterThan(0)
        ->and(MfaRecoveryCode::query()->where('user_id', $id)->count())->toBe(4)
        ->and(WebAuthnCredential::query()->where('user_id', $id)->count())->toBe(1)
        ->and(IdentityLink::query()->where('user_id', $id)->count())->toBe(1)
        ->and(app(SessionManager::class)->active($earlierSession))->not->toBeNull()
        ->and(UserApiToken::query()->withoutGlobalScopes()->whereKey($tokenId)->value('revoked_at'))->toBeNull()
        ->and($grants->revoked)->toBe([])
        ->and(AuditEntry::query()->where('action', 'user.unverified_account_claimed')->exists())->toBeFalse();
}

it('withdraws everything set on an unverified account when a sign-in link proves its mailbox', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('owner@acme.test', verified: false);
    $magic = app(MagicLink::class);

    $session = $magic->redeem($magic->request('owner@acme.test'));

    expect($session->user_id)->toBe($id)
        ->and(app(SessionManager::class)->active($session->id))->not->toBeNull();
    expectClaimed($id, $earlier, $tokenId, $this->grants);
});

it('signs in to a verified account through a sign-in link without touching it', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('owner@acme.test', verified: true);
    $magic = app(MagicLink::class);

    $session = $magic->redeem($magic->request('owner@acme.test'));

    expect($session->user_id)->toBe($id);
    expectUntouched($id, $earlier, $tokenId, $this->grants);
});

it('marks an account a sign-in link created as verified', function (): void {
    $magic = app(MagicLink::class);

    $session = $magic->redeem($magic->request('new@acme.test'));

    expect(app(Subjects::class)->find($session->user_id)?->emailVerified)->toBeTrue();
});

it('claims an unverified account under the invited address before the membership lands on it', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('invitee@acme.test', verified: false);
    $org = mailboxOrg();
    $invitations = app(Invitations::class);
    $pending = $invitations->invite($org->id, 'Invitee@Acme.test', MembershipRole::Admin);

    $membership = $invitations->accept($pending->token, $id);

    expect($membership->user_id)->toBe($id);
    expectClaimed($id, $earlier, $tokenId, $this->grants);
});

it('leaves a verified account alone when it accepts an invitation', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('invitee@acme.test', verified: true);
    $org = mailboxOrg();
    $invitations = app(Invitations::class);

    $invitations->accept($invitations->invite($org->id, 'invitee@acme.test', MembershipRole::Member)->token, $id);

    expectUntouched($id, $earlier, $tokenId, $this->grants);
});

it('leaves an account under another address alone when it accepts an invitation', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('someone.else@acme.test', verified: false);
    $org = mailboxOrg();
    $invitations = app(Invitations::class);

    $invitations->accept($invitations->invite($org->id, 'invitee@acme.test', MembershipRole::Member)->token, $id);

    expectUntouched($id, $earlier, $tokenId, $this->grants);
    expect(app(Subjects::class)->find($id)?->emailVerified)->toBeFalse();
});

it('does nothing when the proven address is not the account\'s', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('owner@acme.test', verified: false);
    $subject = app(Subjects::class)->find($id);
    assert($subject !== null);

    $result = app(MailboxProof::class)->claim($subject, 'other@acme.test');

    expect($result->emailVerified)->toBeFalse();
    expectUntouched($id, $earlier, $tokenId, $this->grants);
});

it('decides on the account as it stands, not on a stale copy', function (): void {
    [$id, $earlier, $tokenId] = credentialedAccount('owner@acme.test', verified: false);
    $stale = app(Subjects::class)->find($id);
    assert($stale !== null);
    User::query()->whereKey($id)->update(['email_verified_at' => now()]);

    $result = app(MailboxProof::class)->claim($stale, 'owner@acme.test');

    expect($result->emailVerified)->toBeTrue();
    expectUntouched($id, $earlier, $tokenId, $this->grants);
});
