<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Enums\WebhookEventGroup;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Cbox\Id\Webhooks\ValueObjects\WebhookEventDescriptor;

/**
 * The catalogue is what consoles, APIs and docs render instead of keeping their own lists,
 * so it has to be complete, ordered, and honest about which events actually fire.
 */
it('describes every catalogued event once, grouped in display order', function (): void {
    $catalogue = WebhookEventType::catalogue();

    expect($catalogue)->toHaveCount(count(WebhookEventType::cases()));

    $names = array_map(fn (WebhookEventDescriptor $d): string => $d->name(), $catalogue);
    expect(array_unique($names))->toHaveCount(count($names));

    $groupOrder = array_flip(array_map(fn (WebhookEventGroup $g): string => $g->value, WebhookEventGroup::cases()));
    $positions = array_map(fn (WebhookEventDescriptor $d): int => $groupOrder[$d->group->value], $catalogue);
    $sorted = $positions;
    sort($sorted);

    expect($positions)->toBe($sorted);

    foreach ($catalogue as $entry) {
        expect($entry->label)->not->toBe('')
            ->and(strlen($entry->description))->toBeGreaterThan(20);
    }
});

it('catalogues the tenancy lifecycle, api key and support events other packages emit', function (): void {
    foreach ([
        'membership.created', 'membership.updated', 'membership.deleted',
        'invitation.created', 'invitation.accepted', 'invitation.revoked',
        'organization.updated', 'organization.deleted',
        'api_key.created', 'api_key.revoked', 'support_session.started',
        'user.login', 'identity.linked', 'role.unassigned', 'role.assigned_everywhere',
    ] as $name) {
        expect(WebhookEventType::tryFrom($name))->not->toBeNull()
            ->and(WebhookEventType::subscribable($name))->toBeTrue()
            ->and(WebhookEventType::from($name)->describe()->isOffered())->toBeTrue();
    }
});

it('points every legacy name at the event that replaced it, and does not offer it', function (): void {
    expect(WebhookEventType::OrganizationMemberAdded->supersededBy())->toBe(WebhookEventType::MembershipCreated)
        ->and(WebhookEventType::OrganizationInvitationAccepted->supersededBy())->toBe(WebhookEventType::InvitationAccepted)
        ->and(WebhookEventType::OrganizationArchived->supersededBy())->toBe(WebhookEventType::OrganizationDeleted);

    foreach (WebhookEventType::cases() as $case) {
        $replacement = $case->supersededBy();

        if ($replacement !== null) {
            expect($replacement->supersededBy())->toBeNull()
                ->and(WebhookEventType::offered())->not->toContain($case);
        }
    }
});

it('emits every catalogued event, and offers every one that is not superseded', function (): void {
    // The nine that were audit-only until 1.19 are emitted where their change happens —
    // tests/Feature/Webhooks/AuditOnlyEventsEmittedTest.php proves each one reaches the bus.
    foreach (WebhookEventType::cases() as $case) {
        expect($case->isEmitted())->toBeTrue()
            ->and($case->describe()->isOffered())->toBe($case->supersededBy() === null);
    }

    expect(WebhookEventType::offered())->toContain(WebhookEventType::DomainVerified)
        ->and(WebhookEventType::offered())->not->toContain(WebhookEventType::OrganizationSettingsUpdated);
});

/**
 * "Emitted" is a claim about the source tree, so it is checked against the source tree: an
 * event the catalogue says fires must be named in a file that puts events on the bus. It is
 * a coarse check — it proves the name is spelled somewhere an emission could be, not that
 * every path reaches it — and it is the one that catches a case added to the catalogue with
 * no code behind it.
 */
it('backs every event it calls emitted with a source file that emits events', function (): void {
    $sources = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 3).'/src')) as $file) {
        $path = (string) $file;

        if (str_ends_with($path, '.php') && ! str_contains($path, '/Webhooks/Enums/')) {
            $contents = (string) file_get_contents($path);

            if (str_contains($contents, 'DomainEvent')) {
                $sources[] = $contents;
            }
        }
    }

    $unbacked = [];

    foreach (WebhookEventType::cases() as $case) {
        if (! $case->isEmitted()) {
            continue;
        }

        $named = array_filter($sources, fn (string $source): bool => str_contains($source, "'{$case->value}'")
            || str_contains($source, "\"{$case->value}\""));

        if ($named === []) {
            $unbacked[] = $case->value;
        }
    }

    expect($unbacked)->toBe([]);
});
