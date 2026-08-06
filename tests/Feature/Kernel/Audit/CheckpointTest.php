<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\Models\AuditEntry;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('signs a checkpoint that verifies against the platform keys', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $head = $log->record(AuditEvent::forSystem('b'));

    $checkpoint = $log->checkpoint(null);

    expect($checkpoint->root_hash)->toBe($head->hash)
        ->and($checkpoint->up_to_sequence)->toBe(2);

    // The signature is a real Crypto-kernel JWT over the chain head.
    $claims = app(TokenSigner::class)->verify($checkpoint->signature, [SigningAlg::RS256]);

    expect($claims->get('root_hash'))->toBe($head->hash)
        ->and($claims->string('typ'))->toBe('cbox-id.audit.checkpoint');
});

it('refuses to checkpoint a scope with no entries', function (): void {
    expect(fn () => app(AuditLog::class)->checkpoint(null))
        ->toThrow(CannotCheckpointEmptyScope::class);
});

it('still verifies a valid, checkpointed chain (no false positive)', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->checkpoint(null);

    expect($log->verifyChain(null)->valid)->toBeTrue();
});

it('detects deletion of checkpointed history (tail truncation)', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->record(AuditEvent::forSystem('b'));
    $log->record(AuditEvent::forSystem('c'));
    $log->checkpoint(null); // anchors sequence 3

    AuditEntry::query()->where('sequence', 3)->delete();

    expect($log->verifyChain(null)->valid)->toBeFalse();
});

it('detects a wiped scope once it has been checkpointed', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->checkpoint(null);

    AuditEntry::query()->delete();

    expect($log->verifyChain(null)->valid)->toBeFalse();
});

/**
 * The signature is the only thing that makes a checkpoint unforgeable, and nothing
 * exercised it.
 *
 * The existing truncation tests are all caught one step later, by the anchor comparison:
 * the checkpoint still claims a root hash no surviving entry has. An attacker with write
 * access to the database does not stop there. They truncate the tail AND rewrite
 * `root_hash` and `up_to_sequence` to describe the shortened chain — at which point the
 * anchor matches, and the only remaining evidence is that the stored payload no longer
 * agrees with what was signed.
 *
 * That comparison could be deleted with the whole suite green, which would reduce the
 * tamper-evidence story to "we hash things and then trust whoever can write the row".
 */
it('refuses a checkpoint whose payload was rewritten to match a truncated chain', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $second = $log->record(AuditEvent::forSystem('b'));
    $log->record(AuditEvent::forSystem('c'));

    $log->checkpoint(null);

    // Cut the tail, then make the checkpoint describe the shorter chain — signature
    // untouched, because the attacker cannot produce a new one.
    AuditEntry::query()->where('sequence', 3)->delete();

    DB::table('audit_checkpoints')->update([
        'root_hash' => $second->hash,
        'up_to_sequence' => 2,
    ]);

    $verification = $log->verifyChain(null);

    expect($verification->valid)->toBeFalse('a rewritten checkpoint passed as authentic')
        ->and($verification->reason)->toContain('does not match its signature');
});

it('refuses a checkpoint whose signature was replaced with something unverifiable', function (): void {
    $log = app(AuditLog::class);
    $log->record(AuditEvent::forSystem('a'));
    $log->checkpoint(null);

    DB::table('audit_checkpoints')->update(['signature' => 'not.a.jwt']);

    $verification = $log->verifyChain(null);

    expect($verification->valid)->toBeFalse()
        ->and($verification->reason)->toContain('signature failed to verify');
});
