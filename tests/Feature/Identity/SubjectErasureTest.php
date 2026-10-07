<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\ErasureStep;
use Cbox\Id\Identity\Contracts\ErasureSteps;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\SessionManager;
use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Enums\UserStatus;
use Cbox\Id\Identity\Exceptions\ErasureRefused;
use Cbox\Id\Identity\Models\MagicLinkToken;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\MfaRecoveryCode;
use Cbox\Id\Identity\Models\PasswordResetToken;
use Cbox\Id\Identity\Models\Session;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Identity\ValueObjects\ErasureRequest;
use Cbox\Id\Identity\ValueObjects\ErasureStepResult;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditActor;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Organization\Models\Membership;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Cbox\Id\Provisioning\Enums\DeprovisionPolicy;
use Cbox\Id\Provisioning\Models\ProvisionedResource;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\Models\VaultSecret;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['cbox-id.provisioning.verify_url' => false]);
});

/*
 * GDPR Art. 17. One call erases a person from every store the package keeps them in,
 * keeps their opaque id, and leaves the hash-chained audit trail verifiable.
 */

/** A subject with something in every store an erasure must reach. Returns [subject id, org id]. */
function richSubject(string $email = 'erase.me@example.test'): array
{
    $subject = app(Subjects::class)->create($email, 'Erin Erasable', 'a-strong-unbreached-passphrase');

    $org = app(Organizations::class)->create(new NewOrganization(name: 'Northwind', slug: 'northwind-'.Str::lower(Str::random(6))));
    $owner = app(Subjects::class)->create('owner-'.Str::random(6).'@example.test', 'Owner', 'a-strong-unbreached-passphrase');
    app(Memberships::class)->add($org->id, $owner->id, MembershipRole::Owner);
    app(Memberships::class)->add($org->id, $subject->id, MembershipRole::Member);

    app(SessionManager::class)->start($subject->id, $org->id, ['pwd'], '203.0.113.7', 'Mozilla/5.0 (Erin’s laptop)');

    app(Mfa::class)->enrollTotp($subject->id, $email);
    app(Mfa::class)->generateRecoveryCodes($subject->id, 4);

    PasswordResetToken::query()->create(['email' => $email, 'token_hash' => hash('sha256', 'r'), 'expires_at' => now()->addHour()]);
    MagicLinkToken::query()->create(['email' => $email, 'token_hash' => hash('sha256', 'm'), 'expires_at' => now()->addHour()]);

    app(SecretVault::class)->store('github', 'github', 'gho_personal', VaultOwner::user($subject->id));

    return [$subject->id, $org->id];
}

it('erases a subject from every store and returns a receipt of what it did', function (): void {
    [$id, $orgId] = richSubject();

    $receipt = app(SubjectEraser::class)->erase($id, AuditActor::operator('op-1'));

    expect($receipt->subjectId)->toBe($id)
        ->and($receipt->subjectPseudonymised)->toBeTrue()
        ->and($receipt->count('memberships'))->toBe(1)
        ->and($receipt->count('sessions_revoked'))->toBe(1)
        ->and($receipt->count('sessions_scrubbed'))->toBe(1)
        ->and($receipt->count('mfa_factors'))->toBe(1)
        ->and($receipt->count('recovery_codes'))->toBe(4)
        ->and($receipt->count('password_reset_tokens'))->toBe(1)
        ->and($receipt->count('magic_links'))->toBe(1)
        ->and($receipt->count('vault_secrets'))->toBe(1)
        ->and($receipt->step('oauth.grants'))->not->toBeNull()
        ->and($receipt->toArray()['steps'])->not->toBeEmpty();

    // Credentials and sessions are gone or dead.
    expect(MfaFactor::query()->where('user_id', $id)->exists())->toBeFalse()
        ->and(MfaRecoveryCode::query()->where('user_id', $id)->exists())->toBeFalse()
        ->and(Session::query()->where('user_id', $id)->whereNull('revoked_at')->exists())->toBeFalse()
        ->and(Session::query()->where('user_id', $id)->whereNotNull('ip')->exists())->toBeFalse()
        ->and(Membership::query()->withoutGlobalScopes()->where('user_id', $id)->exists())->toBeFalse()
        ->and(VaultSecret::query()->where('owner_id', $id)->exists())->toBeFalse();

    // A tombstone and an event, neither carrying PII.
    $tombstone = AuditEntry::query()->where('action', 'user.erased')->where('target_id', $id)->firstOrFail();

    expect($receipt->auditEntryId)->toBe($tombstone->id)
        ->and($tombstone->actor_id)->toBe('op-1')
        ->and(json_encode($tombstone->context))->not->toContain('erase.me')
        ->and(Event::query()->where('type', 'user.erased')->exists())->toBeTrue();
})->group('security');

it('leaves no email, name or password on the subject row, and keeps the id', function (): void {
    [$id] = richSubject();

    $receipt = app(SubjectEraser::class)->erase($id);

    $row = User::query()->findOrFail($id);

    expect(DB::table('users')->where('email', 'like', '%erase.me%')->exists())->toBeFalse('the email is still in the subjects table')
        ->and(DB::table('users')->where('name', 'Erin Erasable')->exists())->toBeFalse()
        ->and($row->email)->toBe($receipt->pseudonym?->email)
        ->and($row->email)->toEndWith('@erased.invalid')
        ->and($row->name)->toBe($receipt->pseudonym?->name)
        ->and($row->password)->toBeNull()
        ->and($row->email_verified_at)->toBeNull()
        ->and($row->status)->toBe(UserStatus::Disabled)
        ->and(app(Subjects::class)->isActive($id))->toBeFalse();
})->group('security');

it('keeps the audit chain verifiable after an erasure', function (): void {
    [$id, $orgId] = richSubject();

    $audit = app(AuditLog::class);

    expect($audit->verifyChain()->valid)->toBeTrue()
        ->and($audit->verifyChain($orgId)->valid)->toBeTrue();

    app(SubjectEraser::class)->erase($id);

    // Nothing hashed was rewritten — and the tombstone extends the chain like any entry.
    expect($audit->verifyChain()->valid)->toBeTrue()
        ->and($audit->verifyChain($orgId)->valid)->toBeTrue()
        ->and(AuditEntry::query()->where('action', 'user.erased')->exists())->toBeTrue();
})->group('security');

it('scrubs the email from the domain-event outbox', function (): void {
    [$id] = richSubject();

    expect(Event::query()->where('payload', 'like', '%erase.me@example.test%')->exists())->toBeTrue('fixture: user.created carries the email');

    $receipt = app(SubjectEraser::class)->erase($id);

    expect(Event::query()->where('payload', 'like', '%erase.me@example.test%')->exists())->toBeFalse()
        ->and($receipt->count('events'))->toBeGreaterThan(0);
})->group('security');

it('refuses to erase the only owner of an organization, and changes nothing', function (): void {
    $subject = app(Subjects::class)->create('sole.owner@example.test', 'Sole', 'a-strong-unbreached-passphrase');
    $org = $this->makeOrganization('Solo');
    app(Memberships::class)->add($org->id, $subject->id, MembershipRole::Owner);
    app(SessionManager::class)->start($subject->id, $org->id, ['pwd']);

    try {
        app(SubjectEraser::class)->erase($subject->id);
        $this->fail('a sole owner was erased');
    } catch (ErasureRefused $refused) {
        expect($refused->organizationIds())->toBe([$org->id]);
    }

    expect(User::query()->findOrFail($subject->id)->email)->toBe('sole.owner@example.test')
        ->and(Session::query()->where('user_id', $subject->id)->whereNull('revoked_at')->exists())->toBeTrue()
        ->and(AuditEntry::query()->where('action', 'user.erased')->exists())->toBeFalse();
})->group('security');

it('deletes the person from every downstream app over SCIM, whatever the deprovision policy', function (): void {
    $fake = $this->fakeScimClient();
    $connection = $this->registerProvisioningConnection(deprovisionPolicy: DeprovisionPolicy::Deactivate)->connection;

    $user = $this->makeUser('downstream@example.test', 'Down Stream');
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    $remoteId = ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id');
    expect($remoteId)->toBeString();

    app(SubjectEraser::class)->erase($user->id);
    $this->relayEvents();
    $this->drainProvisioning($connection->id);

    $deletes = $fake->requestsOfType('delete');

    expect($deletes)->toHaveCount(1)
        ->and($deletes[0]['remoteId'])->toBe($remoteId)
        // And no create/update re-sent the person's data after the erasure.
        ->and($fake->requestsOfType('create'))->toHaveCount(1)
        ->and(ProvisionedResource::query()->where('user_id', $user->id)->value('remote_id'))->toBeNull()
        ->and(DB::table('provisioning_operations')->where('payload', 'like', '%downstream@example.test%')->exists())->toBeFalse();
})->group('security');

it('runs steps a host registers, and lists them on the receipt', function (): void {
    $seen = new ArrayObject;

    app(ErasureSteps::class)->register(new class($seen) implements ErasureStep
    {
        /** @param  ArrayObject<int, string>  $seen */
        public function __construct(private readonly ArrayObject $seen) {}

        public function name(): string
        {
            return 'host.crm';
        }

        public function erase(ErasureRequest $request): ErasureStepResult
        {
            // The PII is handed over BEFORE the subject row is rewritten.
            $this->seen->append((string) $request->email);

            return ErasureStepResult::of('host.crm', ['crm_contacts' => 3]);
        }
    });

    $subject = $this->makeUser('hosted@example.test');

    $receipt = app(SubjectEraser::class)->erase($subject->id);

    expect($seen->getArrayCopy())->toBe(['hosted@example.test'])
        ->and($receipt->step('host.crm')?->count('crm_contacts'))->toBe(3);
});

it('can be retried: erasing an erased subject is a no-op that still succeeds', function (): void {
    [$id] = richSubject();

    $first = app(SubjectEraser::class)->erase($id);
    $second = app(SubjectEraser::class)->erase($id);

    expect($second->pseudonym?->email)->toBe($first->pseudonym?->email)
        ->and($second->count('memberships'))->toBe(0)
        ->and(User::query()->findOrFail($id)->email)->toBe($first->pseudonym?->email);
});
