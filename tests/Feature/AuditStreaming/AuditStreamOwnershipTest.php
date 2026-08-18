<?php

declare(strict_types=1);

use Cbox\Id\AuditStreaming\Models\AuditStream;
use Cbox\Id\AuditStreaming\Models\AuditStreamDelivery;
use Cbox\Id\Kernel\Audit\Contracts\AuditLog;
use Cbox\Id\Kernel\Audit\ValueObjects\AuditEvent;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['siem.http.verify_url' => false]));

/*
 * A TENANT'S SIEM RECEIVES THAT TENANT'S EVENTS, NOT THE ENVIRONMENT'S.
 *
 * A stream was environment-owned and nothing more: every entry recorded anywhere in the
 * environment went to every enabled stream in it. That was right while only an operator
 * could configure one — and the console has since put log streaming on the ORGANIZATION
 * plane, on the fair argument that shipping an audit trail to a SIEM is a compliance
 * obligation the organization carries. Together they meant an administrator of
 * organization A registered their own endpoint and started receiving organizations B and
 * C's sign-ins, role changes and member events. Not a leak anyone had to work for: the
 * feature working exactly as built, on a plane that was never in its design.
 */
it('delivers an organization event only to that organization and to the environment', function (): void {
    $ownedByA = $this->registerAuditStream('acme-splunk', organizationId: 'org_a');
    $ownedByB = $this->registerAuditStream('other-splunk', organizationId: 'org_b');
    // No organization: the environment's own, which is what every stream used to be.
    $environmentWide = $this->registerAuditStream('operator-splunk');

    app(AuditLog::class)->record(new AuditEvent(
        action: 'member.invited',
        organizationId: 'org_a',
    ));

    $deliveries = fn (string $streamId): int => AuditStreamDelivery::query()
        ->where('stream_id', $streamId)->count();

    expect($deliveries($ownedByA->stream->id))->toBe(1)
        ->and($deliveries($environmentWide->stream->id))->toBe(1)
        // The whole point.
        ->and($deliveries($ownedByB->stream->id))->toBe(0);
})->group('security');

it('sends a platform-level event to the environment only, because no tenant owns it', function (): void {
    $ownedByA = $this->registerAuditStream('acme-splunk', organizationId: 'org_a');
    $environmentWide = $this->registerAuditStream('operator-splunk');

    // No organization on the event: a platform-level action belongs to no tenant, so
    // there is no tenant entitled to hear about it.
    app(AuditLog::class)->record(AuditEvent::forSystem('config.changed'));

    $deliveries = fn (string $streamId): int => AuditStreamDelivery::query()
        ->where('stream_id', $streamId)->count();

    expect($deliveries($environmentWide->stream->id))->toBe(1)
        ->and($deliveries($ownedByA->stream->id))->toBe(0);
})->group('security');

/*
 * The two scopes ask different questions and the difference IS the control: an
 * organization is DELIVERED the environment's streams' attention and must never be able
 * to MANAGE them. A console that listed streams with the delivery scope would show a
 * tenant the operator's own SIEM endpoint, and offer them a pause button for it.
 */
it('separates the streams an organization receives from the ones it owns', function (): void {
    $ownedByA = $this->registerAuditStream('acme-splunk', organizationId: 'org_a');
    $environmentWide = $this->registerAuditStream('operator-splunk');

    $deliverable = AuditStream::query()
        ->deliverableFor('org_a')->pluck('id')->all();
    $owned = AuditStream::query()
        ->ownedByOrganization('org_a')->pluck('id')->all();

    expect($deliverable)->toContain($ownedByA->stream->id)
        ->and($deliverable)->toContain($environmentWide->stream->id)
        ->and($owned)->toBe([$ownedByA->stream->id]);
})->group('security');
