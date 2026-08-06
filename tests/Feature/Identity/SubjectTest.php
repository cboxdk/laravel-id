<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\Subjects;
use Cbox\Id\Identity\Models\User;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Events\Models\Event;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/**
 * The console changed a user's name and email with a raw `$user->save()` — the only
 * direct model write left in it, because the contract had no verb for this. Three things
 * followed from that: no audit record for the most security-relevant mutable attribute on
 * an account (email is both the primary identifier and the recovery channel);
 * `user.updated` offered in the webhook picker with nothing emitting it; and the outbound
 * SCIM path's `user.updated => Upsert` branch permanently dead, so a legal name change
 * reached no downstream application, ever.
 */
it('audits and announces a profile change, and unverifies a changed email', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('before@acme.test', 'Before', 'a-perfectly-long-passphrase');
    $subjects->markEmailVerified($subject->id, 'before@acme.test');

    expect(User::query()->whereKey($subject->id)->value('email_verified_at'))->not->toBeNull();

    $subjects->update($subject->id, 'After', 'after@acme.test');

    $row = User::query()->whereKey($subject->id)->firstOrFail();

    expect($row->name)->toBe('After')
        ->and($row->email)->toBe('after@acme.test')
        // An administrator asserting an address is not its owner proving one. Keeping the
        // verified flag would make this an account-takeover primitive: set an address you
        // control, and every recovery path now points at you.
        ->and($row->email_verified_at)->toBeNull();

    expect(AuditEntry::query()->where('action', 'user.updated')->where('target_id', $subject->id)->exists())->toBeTrue();
    expect(Event::query()->where('type', 'user.updated')->exists())->toBeTrue('nothing emitted user.updated');
});

/**
 * A no-op write must not manufacture an audit entry or a webhook — an access review
 * reading "the email changed" when it did not is worse than silence.
 */
it('records nothing when a profile save changes nothing', function (): void {
    $subjects = app(Subjects::class);
    $subject = $subjects->create('same@acme.test', 'Same', 'a-perfectly-long-passphrase');

    $before = AuditEntry::query()->count();
    $subjects->update($subject->id, 'Same', 'same@acme.test');

    expect(AuditEntry::query()->count())->toBe($before)
        ->and(Event::query()->where('type', 'user.updated')->exists())->toBeFalse();
});
