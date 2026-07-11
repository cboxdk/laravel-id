<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;

it('fakes the event bus and asserts emitted events', function (): void {
    $events = $this->fakeEvents();

    app(EventBus::class)->emit(new DomainEvent('organization.created', ['id' => 'org_1'], 'org_1'));

    $events->assertEmitted('organization.created');
    $events->assertEmitted('organization.created', fn (DomainEvent $e): bool => $e->organizationId === 'org_1');
    $events->assertNotEmitted('organization.deleted');
    $events->assertEmittedCount(1);
});

it('asserts nothing emitted', function (): void {
    $events = $this->fakeEvents();

    $events->assertNothingEmitted();
});
