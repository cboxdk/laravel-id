<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\ValueObjects\ImportedUser;
use Cbox\Id\Migration\Contracts\LegacyCredentialSource;
use Cbox\Id\Migration\Events\UserMigrated;
use Cbox\Id\Migration\LegacyMigration;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Psr\Log\LoggerInterface;

uses(RefreshDatabase::class);

/**
 * A source that answers whatever the test needs, including by throwing.
 */
function sourceThat(?ImportedUser $answer, ?Throwable $throws = null): LegacyCredentialSource
{
    return new class($answer, $throws) implements LegacyCredentialSource
    {
        public int $calls = 0;

        public function __construct(private readonly ?ImportedUser $answer, private readonly ?Throwable $throws) {}

        public function verify(string $email, string $password): ?ImportedUser
        {
            $this->calls++;

            if ($this->throws !== null) {
                throw $this->throws;
            }

            return $this->answer;
        }

        public function find(string $email): ?ImportedUser
        {
            return $this->answer;
        }
    };
}

function migrationOver(LegacyCredentialSource $source): LegacyMigration
{
    return new LegacyMigration(
        $source,
        app(Subjects::class),
        app(Dispatcher::class),
        app(LoggerInterface::class),
    );
}

/**
 * THE TRAP THIS WHOLE FEATURE CAN FALL INTO. `create()` hashes what it is handed, so
 * passing a foreign hash there hashes the hash — and the person's password stops working
 * at the exact moment they migrate, in a way indistinguishable from them mistyping it.
 */
it('carries a foreign hash verbatim, so the password still works afterwards', function (): void {
    $hash = password_hash('correct horse', PASSWORD_BCRYPT);

    $subject = migrationOver(sourceThat(new ImportedUser(
        email: 'ada@legacy.test',
        name: 'Ada',
        passwordHash: $hash,
    )))->migrate('ada@legacy.test', 'correct horse');

    expect($subject)->not->toBeNull();

    // The proof that matters: they can sign in again, through the ordinary local path.
    expect(app(Subjects::class)->verifyPassword($subject->id, 'correct horse'))->toBeTrue();
});

/**
 * An opaque API can prove the credential without handing over its hash. Hashing what the
 * person just proved they know is the only other honest option.
 */
it('hashes the proven password when the old system cannot hand over its hash', function (): void {
    $subject = migrationOver(sourceThat(new ImportedUser(
        email: 'grace@legacy.test',
        name: 'Grace',
    )))->migrate('grace@legacy.test', 'a-long-proven-passphrase');

    expect(app(Subjects::class)->verifyPassword($subject->id, 'a-long-proven-passphrase'))->toBeTrue()
        ->and(app(Subjects::class)->verifyPassword($subject->id, 'something-else'))->toBeFalse();
});

/**
 * FAIL CLOSED. A source that throws has not said the password is wrong — it has said it
 * could not decide, and letting an undecided answer through turns an outage in the system
 * you are migrating OFF into an authentication bypass.
 */
it('refuses the sign-in when the old system cannot answer', function (): void {
    $subject = migrationOver(sourceThat(null, new RuntimeException('connection refused')))
        ->migrate('ada@legacy.test', 'correct horse');

    expect($subject)->toBeNull()
        ->and(app(Subjects::class)->findByEmail('ada@legacy.test'))->toBeNull();
});

it('refuses, and creates nobody, when the old system says no', function (): void {
    $subject = migrationOver(sourceThat(null))->migrate('nobody@legacy.test', 'wrong');

    expect($subject)->toBeNull()
        ->and(app(Subjects::class)->findByEmail('nobody@legacy.test'))->toBeNull();
});

/**
 * The seam that keeps this class from growing a policy it should not own: a host attaches
 * the person to an organization from here, and needs the LEGACY record to do it.
 */
it('announces the migration with both sides of the person', function (): void {
    Event::fake([UserMigrated::class]);

    migrationOver(sourceThat(new ImportedUser(
        email: 'ada@legacy.test',
        name: 'Ada',
        passwordHash: password_hash('pw', PASSWORD_BCRYPT),
        role: 'admin',
    )))->migrate('ada@legacy.test', 'pw');

    Event::assertDispatched(UserMigrated::class, function (UserMigrated $e): bool {
        return $e->subject->email === 'ada@legacy.test' && $e->legacy->role === 'admin';
    });
});

/**
 * Two tabs, one unique index. Losing that race is not a failed login — the user exists
 * now, and returning them is the honest answer.
 */
it('returns the existing subject when two sign-ins race', function (): void {
    $source = sourceThat(new ImportedUser(email: 'ada@legacy.test', passwordHash: password_hash('pw', PASSWORD_BCRYPT)));

    $first = migrationOver($source)->migrate('ada@legacy.test', 'pw');
    $second = migrationOver($source)->migrate('ada@legacy.test', 'pw');

    expect($second?->id)->toBe($first?->id);
});
