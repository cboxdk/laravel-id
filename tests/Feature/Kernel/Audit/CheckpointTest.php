<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\Exceptions\CannotCheckpointEmptyScope;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Cbox\Id\Kernel\Crypto\Contracts\TokenSigner;
use Cbox\Id\Kernel\Crypto\Enums\SigningAlg;
use Illuminate\Foundation\Testing\RefreshDatabase;

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
