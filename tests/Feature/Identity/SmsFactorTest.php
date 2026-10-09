<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\AuthPolicies;
use Cbox\Id\Identity\Contracts\Mfa;
use Cbox\Id\Identity\Contracts\MfaMandate;
use Cbox\Id\Identity\Contracts\PrivilegedSubjects;
use Cbox\Id\Identity\Contracts\SmsFactorPolicies;
use Cbox\Id\Identity\Contracts\SmsFactors;
use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Identity\Enums\MfaRequirement;
use Cbox\Id\Identity\Enums\SmsFactorRefusal;
use Cbox\Id\Identity\Exceptions\SmsFactorRefused;
use Cbox\Id\Identity\Models\MfaFactor;
use Cbox\Id\Identity\Models\WebAuthnCredential;
use Cbox\Id\Identity\ValueObjects\AuthPolicy;
use Cbox\Id\Identity\ValueObjects\SmsFactorPolicy;
use Cbox\Id\Kernel\Audit\Enums\ActorType;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Crypto\Contracts\SealedColumns;
use Cbox\Id\Kernel\Crypto\Exceptions\DecryptionFailed;
use Cbox\Id\Kernel\Crypto\TotpAuthenticator;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\Otp\Contracts\OtpService;
use Cbox\Id\Otp\Exceptions\OtpRateLimitExceeded;
use Cbox\Id\Otp\Models\OtpChallenge;
use Cbox\Id\Otp\Sms\Contracts\SmsSender;
use Cbox\Id\Otp\Sms\Contracts\SmsSendGuard;
use Cbox\Id\Otp\Sms\Exceptions\SmsSendRefused;
use Cbox\Id\Otp\Sms\Senders\ArraySmsSender;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Cache::flush();
    // No cooldown here: several tests text one number twice on purpose. The cooldown has
    // its own test below and in the guard's suite.
    config()->set('cbox-id.sms.limits.cooldown_seconds', 0);
});

function allowSms(array $countries = ['DK', 'SE'], bool $privilegedNeedStronger = true): void
{
    app(SmsFactorPolicies::class)->setForEnvironment(new SmsFactorPolicy(true, $countries, $privilegedNeedStronger));
}

function sms(): SmsFactors
{
    return app(SmsFactors::class);
}

/** Enrol and confirm `+4512345678` for a user; returns the fake that caught the texts. */
function enrolledSms(string $userId, string $number = '+4512345678'): ArraySmsSender
{
    $fake = app(SmsSender::class);

    if (! $fake instanceof ArraySmsSender) {
        $fake = new ArraySmsSender;
        app()->instance(SmsSender::class, $fake);
    }

    sms()->beginEnrolment($userId, $number);
    expect(sms()->confirmEnrolment($userId, (string) $fake->latestCode()))->toBeTrue();

    return $fake;
}

function withPrivileged(bool $privileged): void
{
    app()->instance(PrivilegedSubjects::class, new class($privileged) implements PrivilegedSubjects
    {
        public function __construct(private readonly bool $answer) {}

        public function isPrivileged(string $subjectId): bool
        {
            return $this->answer;
        }
    });
    app()->forgetInstance(SmsFactors::class);
    app()->forgetInstance(MfaMandate::class);
}

it('is off by default and refuses to enrol anyone', function (): void {
    $fake = $this->fakeSms();

    expect(app(SmsFactorPolicies::class)->forEnvironment())->toEqual(new SmsFactorPolicy)
        ->and(fn () => sms()->beginEnrolment('user_1', '+4512345678'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::NotEnabled));

    $fake->assertNothingSent();
    expect(MfaFactor::query()->count())->toBe(0);
});

it('enrols a number by texting it a code, and confirms it with that code', function (): void {
    allowSms();
    $fake = $this->fakeSms();

    $sent = sms()->beginEnrolment('user_1', '+45 12 34 56 78', ip: '203.0.113.9');

    expect($sent->maskedNumber)->toBe('+45 ******78')
        ->and(sms()->isEnrolled('user_1'))->toBeFalse()
        ->and(sms()->details('user_1')?->confirmed)->toBeFalse();
    $fake->assertSent('+4512345678');

    expect(sms()->confirmEnrolment('user_1', '000000'))->toBeFalse()
        ->and(sms()->confirmEnrolment('user_1', (string) $fake->latestCode()))->toBeTrue()
        ->and(sms()->isEnrolled('user_1'))->toBeTrue()
        ->and(sms()->isUsable('user_1'))->toBeTrue()
        ->and(sms()->details('user_1'))->toMatchArray(['maskedNumber' => '+45 ******78', 'country' => 'DK', 'confirmed' => true]);

    expect(AuditEntry::query()->where('action', 'user.mfa_enrolled')->sole()->context)->toBe(['type' => 'sms', 'country' => 'DK']);
});

it('accepts a national number with a default country', function (): void {
    allowSms(['SE']);
    $fake = $this->fakeSms();

    sms()->beginEnrolment('user_1', '070-123 45 67', 'SE');

    $fake->assertSent('+46701234567');
});

it('stores the number only sealed, and the OTP tables only an opaque factor id', function (): void {
    allowSms();
    $fake = enrolledSms('user_1');
    sms()->sendChallenge('user_1');

    $row = DB::table('mfa_factors')->where('type', 'sms')->sole();

    expect($row->secret_encrypted)->not->toContain('12345678')
        ->and(DB::table('otp_challenges')->pluck('recipient')->unique()->all())->toBe(['mfa-sms:'.$row->id]);

    foreach (AuditEntry::query()->get() as $entry) {
        expect(json_encode($entry->context))->not->toContain('12345678');
    }

    // Registered for rotation through the existing mfa_factors column.
    $names = array_map(fn ($column) => $column->name(), app(SealedColumns::class)->all());
    expect($names)->toContain('mfa_factors.secret_encrypted');

    $fake->assertSentCount(2);
});

it('binds the sealed number to its owner', function (): void {
    allowSms();
    enrolledSms('user_1');

    // Copy the ciphertext onto someone else's factor: it must not open for them.
    $sealed = MfaFactor::query()->where('user_id', 'user_1')->value('secret_encrypted');
    MfaFactor::query()->create(['user_id' => 'user_2', 'type' => 'sms', 'secret_encrypted' => $sealed, 'confirmed_at' => now()]);

    expect(fn () => sms()->details('user_2'))->toThrow(DecryptionFailed::class);
});

it('refuses a number that is not one, or not in an allowed country', function (): void {
    allowSms(['DK']);
    $fake = $this->fakeSms();

    expect(fn () => sms()->beginEnrolment('user_1', 'call me'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::InvalidNumber))
        ->and(fn () => sms()->beginEnrolment('user_1', '+46701234567'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::CountryNotAllowed))
        ->and(fn () => sms()->beginEnrolment('user_1', '+881612345678'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::InvalidNumber));

    $fake->assertNothingSent();
});

it('admits no country when SMS is on but none is listed', function (): void {
    allowSms([]);

    expect(fn () => sms()->beginEnrolment('user_1', '+4512345678'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::CountryNotAllowed));
});

it('replaces an unconfirmed number but refuses to replace a confirmed one', function (): void {
    allowSms();
    $fake = $this->fakeSms();

    sms()->beginEnrolment('user_1', '+4511111111');
    $first = (string) $fake->latestCode();
    sms()->beginEnrolment('user_1', '+4522222222');

    // The code sent to the abandoned number does not confirm the new one.
    expect(sms()->confirmEnrolment('user_1', $first))->toBeFalse()
        ->and(sms()->confirmEnrolment('user_1', (string) $fake->latestCode('+4522222222')))->toBeTrue()
        ->and(sms()->details('user_1')?->maskedNumber)->toBe('+45 ******22')
        ->and(MfaFactor::query()->where('type', 'sms')->count())->toBe(1);

    expect(fn () => sms()->beginEnrolment('user_1', '+4533333333'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::AlreadyEnrolled));
});

it('challenges at sign-in with a single-use code', function (): void {
    allowSms();
    $fake = enrolledSms('user_1');

    $sent = sms()->sendChallenge('user_1', '203.0.113.9');
    $code = (string) $fake->latestCode();

    expect($sent->maskedNumber)->toBe('+45 ******78')
        ->and(sms()->verifyChallenge('user_1', '000000'))->toBeFalse()
        ->and(sms()->verifyChallenge('user_1', $code))->toBeTrue()
        ->and(sms()->verifyChallenge('user_1', $code))->toBeFalse();
});

it('keeps enrolment codes and sign-in codes apart', function (): void {
    allowSms();
    $fake = $this->fakeSms();

    sms()->beginEnrolment('user_1', '+4512345678');
    $enrolCode = (string) $fake->latestCode();

    // Not confirmed yet: there is no sign-in challenge to send, and the enrolment code
    // completes nothing at sign-in.
    expect(fn () => sms()->sendChallenge('user_1'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::NotEnrolled));

    expect(sms()->confirmEnrolment('user_1', $enrolCode))->toBeTrue();

    sms()->sendChallenge('user_1');
    expect(sms()->confirmEnrolment('user_1', (string) $fake->latestCode()))->toBeFalse();
});

it('texts in the language it is asked for', function (): void {
    allowSms();
    $fake = enrolledSms('user_1');

    sms()->sendChallenge('user_1', locale: 'da');
    expect($fake->latest()?->body)->toContain('bekræftelseskode')
        ->and(app()->getLocale())->toBe('en');
});

it('stops texting and accepting at once when the environment turns SMS off or drops the country', function (): void {
    allowSms(['DK', 'SE']);
    $fake = enrolledSms('user_1');
    sms()->sendChallenge('user_1');
    $pending = (string) $fake->latestCode();

    allowSms(['SE']);

    expect(sms()->isEnrolled('user_1'))->toBeTrue()
        ->and(sms()->isUsable('user_1'))->toBeFalse()
        ->and(sms()->verifyChallenge('user_1', $pending))->toBeFalse()
        ->and(fn () => sms()->sendChallenge('user_1'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::CountryNotAllowed));

    app(SmsFactorPolicies::class)->setForEnvironment(new SmsFactorPolicy(false, ['DK']));

    expect(sms()->isUsable('user_1'))->toBeFalse()
        ->and(fn () => sms()->sendChallenge('user_1'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::NotEnabled));
});

it('puts every send through the toll-fraud guard', function (): void {
    allowSms();
    config()->set('cbox-id.sms.limits.cooldown_seconds', 60);
    app()->forgetInstance(SmsSendGuard::class);
    $fake = enrolledSms('user_1');

    // Enrolment just texted this number; a sign-in code a moment later is held back.
    expect(fn () => sms()->sendChallenge('user_1'))->toThrow(SmsSendRefused::class);
    $fake->assertSentCount(1);
    expect(AuditEntry::query()->where('action', 'sms.refused')->exists())->toBeTrue();
});

it('is bound by the OTP issue caps', function (): void {
    allowSms();
    config()->set('cbox-id.otp.issue.per_recipient_max', 2);
    app()->forgetInstance(OtpService::class);
    app()->forgetInstance(SmsFactors::class);
    enrolledSms('user_1');

    sms()->sendChallenge('user_1');

    expect(fn () => sms()->sendChallenge('user_1'))->toThrow(OtpRateLimitExceeded::class);
});

it('locks a sign-in challenge after the attempt cap', function (): void {
    allowSms();
    $fake = enrolledSms('user_1');
    sms()->sendChallenge('user_1');
    $code = (string) $fake->latestCode();

    foreach (range(1, 5) as $_) {
        sms()->verifyChallenge('user_1', '000000');
    }

    expect(sms()->verifyChallenge('user_1', $code))->toBeFalse()
        ->and(OtpChallenge::query()->where('purpose', SmsFactors::PURPOSE_CHALLENGE)->sole()->isLocked())->toBeTrue();
});

it('removes the SMS factor alone, keeping recovery codes and TOTP, and audits who did it', function (): void {
    allowSms();
    enrolledSms('user_1');
    app(Mfa::class)->generateRecoveryCodes('user_1');
    $totp = app(Mfa::class)->enrollTotp('user_1', 'u@example.test');
    app(Mfa::class)->confirmTotp('user_1', app(TotpAuthenticator::class)->codeAt($totp->secret, time()));

    expect(sms()->remove('user_1', ActorType::Operator, 'admin_7'))->toBeTrue()
        ->and(sms()->details('user_1'))->toBeNull()
        ->and(app(Mfa::class)->hasConfirmedTotp('user_1'))->toBeTrue()
        ->and(app(Mfa::class)->remainingRecoveryCodes('user_1'))->toBe(10)
        ->and(sms()->remove('user_1'))->toBeFalse();

    $entry = AuditEntry::query()->where('action', 'user.mfa_sms_removed')->sole();
    expect($entry->actor_type)->toBe(ActorType::Operator)->and($entry->actor_id)->toBe('admin_7');
});

it('is removed with every other factor by a full MFA reset and by erasure', function (): void {
    allowSms();
    enrolledSms('user_1');
    app(Mfa::class)->disable('user_1');
    expect(sms()->details('user_1'))->toBeNull();

    $user = $this->makeUser('erase@example.test');
    enrolledSms($user->id, '+4587654321');
    app(SubjectEraser::class)->erase($user->id);
    expect(MfaFactor::query()->where('user_id', $user->id)->exists())->toBeFalse();
});

it('cannot be read or texted from another environment', function (): void {
    $fake = $this->fakeSms();

    $this->runAsEnvironment('env_a', function () use ($fake): void {
        allowSms();
        sms()->beginEnrolment('user_1', '+4512345678');
        sms()->confirmEnrolment('user_1', (string) $fake->latestCode());
    });

    $this->runAsEnvironment('env_b', function (): void {
        allowSms();

        expect(sms()->details('user_1'))->toBeNull()
            ->and(sms()->isEnrolled('user_1'))->toBeFalse()
            ->and(fn () => sms()->sendChallenge('user_1'))->toThrow(SmsFactorRefused::class);
    });
});

// ------------------------------------------------------------ administrators

it('refuses SMS as an administrator\'s first factor', function (): void {
    allowSms();
    withPrivileged(true);
    $fake = $this->fakeSms();

    expect(fn () => sms()->beginEnrolment('admin_1', '+4512345678'))
        ->toThrow(fn (SmsFactorRefused $e) => expect($e->reason)->toBe(SmsFactorRefusal::StrongerFactorRequired));
    $fake->assertNothingSent();

    // With a passkey in place, SMS may be added beside it.
    WebAuthnCredential::query()->create(['user_id' => 'admin_1', 'credential_id' => 'cred-1', 'public_key' => 'pk', 'sign_count' => 0]);
    sms()->beginEnrolment('admin_1', '+4512345678');
    $fake->assertSent('+4512345678');
});

it('lets the environment allow SMS alone for administrators', function (): void {
    allowSms(privilegedNeedStronger: false);
    withPrivileged(true);
    $fake = $this->fakeSms();

    sms()->beginEnrolment('admin_1', '+4512345678');

    $fake->assertSent();
});

it('asks an administrator holding SMS alone to enrol a stronger factor, even where MFA is optional', function (): void {
    allowSms();
    withPrivileged(false);
    enrolledSms('user_1');
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Optional));

    expect(sms()->needsStrongerFactor('user_1'))->toBeFalse()
        ->and(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeFalse();

    // Promoted to administrator after enrolling SMS.
    withPrivileged(true);

    expect(sms()->needsStrongerFactor('user_1'))->toBeTrue()
        ->and(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeTrue()
        // …but SMS keeps working meanwhile: refusing it would leave a password alone.
        ->and(sms()->isUsable('user_1'))->toBeTrue();

    $totp = app(Mfa::class)->enrollTotp('user_1', 'u@example.test');
    app(Mfa::class)->confirmTotp('user_1', app(TotpAuthenticator::class)->codeAt($totp->secret, time()));

    expect(sms()->needsStrongerFactor('user_1'))->toBeFalse()
        ->and(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeFalse();
});

it('treats an owner or admin of any organization as privileged by default', function (): void {
    $member = $this->makeUser('member@example.test')->id;
    $admin = $this->makeUser('admin@example.test')->id;
    $org = $this->makeOrganization();

    app(Memberships::class)->add($org->id, $member, MembershipRole::Member);
    app(Memberships::class)->add($org->id, $admin, MembershipRole::Admin);

    $privileged = app(PrivilegedSubjects::class);

    expect($privileged->isPrivileged($member))->toBeFalse()
        ->and($privileged->isPrivileged($admin))->toBeTrue()
        ->and($privileged->isPrivileged('nobody'))->toBeFalse();
});

// ------------------------------------------------------------ the MFA mandate

it('satisfies a required second factor with a usable SMS factor — and only while usable', function (): void {
    allowSms();
    withPrivileged(false);
    app(AuthPolicies::class)->setForEnvironment(new AuthPolicy(mfa: MfaRequirement::Required));

    expect(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeTrue();

    enrolledSms('user_1');
    expect(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeFalse();

    app(SmsFactorPolicies::class)->setForEnvironment(new SmsFactorPolicy(false, ['DK']));
    expect(app(MfaMandate::class)->requiresEnrolment('user_1'))->toBeTrue();
});

it('normalises the stored country list', function (): void {
    app(SmsFactorPolicies::class)->setForEnvironment(new SmsFactorPolicy(true, ['se', ' dk ', 'DK', 'nope', '1', 'SE']));

    expect(app(SmsFactorPolicies::class)->forEnvironment()->allowedCountries)->toBe(['DK', 'SE'])
        ->and(app(SmsFactorPolicies::class)->forEnvironment()->allowsCountry('dk'))->toBeTrue()
        ->and((new SmsFactorPolicy(false, ['DK']))->allowsCountry('DK'))->toBeFalse();
});
