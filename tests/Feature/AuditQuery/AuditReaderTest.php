<?php

declare(strict_types=1);

use Cbox\Id\AuditQuery\Contracts\AuditReader;
use Cbox\Id\AuditQuery\ValueObjects\AuditQueryFilter;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('reads a scope in sequence order', function (): void {
    $log = app(AuditLog::class);
    $log->record(new AuditEvent('a.1', organizationId: 'org_a'));
    $log->record(new AuditEvent('a.2', organizationId: 'org_a'));

    $page = app(AuditReader::class)->query(new AuditQueryFilter(organizationId: 'org_a'));

    expect($page->items)->toHaveCount(2)
        ->and($page->items[0]->action)->toBe('a.1')
        ->and($page->items[1]->action)->toBe('a.2');
});

it('filters by action', function (): void {
    $log = app(AuditLog::class);
    $log->record(new AuditEvent('login', organizationId: 'org_a'));
    $log->record(new AuditEvent('logout', organizationId: 'org_a'));

    $page = app(AuditReader::class)->query(new AuditQueryFilter(organizationId: 'org_a', action: 'login'));

    expect($page->items)->toHaveCount(1)
        ->and($page->items[0]->action)->toBe('login');
});

it('filters by target for a data-subject (DSR) export', function (): void {
    $log = app(AuditLog::class);
    $log->record(new AuditEvent('user.updated', organizationId: 'org_a', targetType: 'user', targetId: 'user_42'));
    $log->record(new AuditEvent('user.updated', organizationId: 'org_a', targetType: 'user', targetId: 'user_99'));
    $log->record(new AuditEvent('user.deleted', organizationId: 'org_a', targetType: 'user', targetId: 'user_42'));

    $page = app(AuditReader::class)->query(new AuditQueryFilter(
        organizationId: 'org_a',
        targetType: 'user',
        targetId: 'user_42',
    ));

    expect($page->items)->toHaveCount(2)
        ->and($page->items[0]->action)->toBe('user.updated')
        ->and($page->items[1]->action)->toBe('user.deleted');
});

it('paginates with a sequence cursor', function (): void {
    $log = app(AuditLog::class);
    foreach (range(1, 5) as $i) {
        $log->record(new AuditEvent("e.{$i}", organizationId: 'org_a'));
    }

    $reader = app(AuditReader::class);
    $page1 = $reader->query(new AuditQueryFilter(organizationId: 'org_a', limit: 2));

    expect($page1->items)->toHaveCount(2)
        ->and($page1->nextCursor)->not->toBeNull();

    $page2 = $reader->query(new AuditQueryFilter(
        organizationId: 'org_a',
        afterSequence: (int) $page1->nextCursor,
        limit: 2,
    ));

    expect($page2->items)->toHaveCount(2)
        ->and($page2->items[0]->action)->toBe('e.3');
});

it('isolates scopes (org vs system)', function (): void {
    $log = app(AuditLog::class);
    $log->record(new AuditEvent('a', organizationId: 'org_a'));
    $log->record(new AuditEvent('b', organizationId: 'org_b'));
    $log->record(new AuditEvent('sys'));

    $reader = app(AuditReader::class);

    expect($reader->query(new AuditQueryFilter(organizationId: 'org_a'))->items)->toHaveCount(1)
        ->and($reader->query(new AuditQueryFilter(organizationId: null))->items)->toHaveCount(1);
});

it('streams entries after a sequence for a SIEM pull', function (): void {
    $log = app(AuditLog::class);
    $log->record(new AuditEvent('1', organizationId: 'org_a'));
    $log->record(new AuditEvent('2', organizationId: 'org_a'));
    $log->record(new AuditEvent('3', organizationId: 'org_a'));

    $entries = app(AuditReader::class)->since('org_a', afterSequence: 1);

    expect($entries)->toHaveCount(2)
        ->and($entries[0]->sequence)->toBe(2);
});
