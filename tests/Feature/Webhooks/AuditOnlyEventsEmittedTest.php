<?php

declare(strict_types=1);

use Cbox\Id\AccessControl\Contracts\Roles;
use Cbox\Id\Federation\Contracts\Connections;
use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Enums\ConnectionType;
use Cbox\Id\Governance\Contracts\AccessReviews;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\Organization\Contracts\Memberships;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Enums\MembershipRole;
use Cbox\Id\TokenVault\Contracts\SecretVault;
use Cbox\Id\TokenVault\ValueObjects\VaultOwner;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * NINE CATALOGUED WEBHOOK EVENTS WERE NEVER DELIVERED.
 *
 * They were offered to subscribers for releases and recorded on the audit trail, but
 * nothing put them on the event bus, so an endpoint subscribed to `domain.verified` — the
 * event that tells an app a customer's SSO domain is live — received nothing, ever. Each
 * is now emitted where its change happens. These tests drive the real service and read
 * the bus: the payload, and the organization it is delivered to.
 */

/** @return list<DomainEvent> */
function emittedOfType(object $bus, string $type): array
{
    return array_values(array_filter($bus->emitted, fn (DomainEvent $event): bool => $event->type === $type));
}

it('emits domain.added, domain.verified and domain.removed to the owning organization', function (): void {
    $events = $this->fakeEvents();
    $dns = $this->fakeDns();
    $org = $this->makeOrganization('Acme');
    $domains = app(DomainVerification::class);

    $domain = $domains->add($org->id, 'acme.test');
    $dns->publish($domains->challengeHost('acme.test'), $domain->verification_token);
    $domains->verify($domain->id);
    // Verifying an already-verified domain changes nothing and announces nothing.
    $domains->verify($domain->id);
    $domains->setCapture($domain->id, true);
    $domains->remove($domain->id);

    foreach (['domain.added', 'domain.verified', 'domain.removed'] as $type) {
        $emitted = emittedOfType($events, $type);

        expect($emitted)->toHaveCount(1)
            ->and($emitted[0]->payload)->toBe(['id' => $domain->id, 'domain' => 'acme.test'])
            ->and($emitted[0]->organizationId)->toBe($org->id);
    }

    // Capture is audited, not catalogued: it stays off the bus.
    expect(emittedOfType($events, 'domain.capture_enabled'))->toBe([]);
});

it('emits connection.activated once, on the change, and audits it', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();
    $org = $this->makeOrganization('Acme');
    $connections = app(Connections::class);
    $connection = $connections->create($org->id, ConnectionType::Oidc, 'Acme Okta', [
        'issuer' => 'https://idp.acme.test', 'client_id' => 'abc', 'client_secret' => 'shh',
    ]);

    $connections->activate($org->id, $connection->id);
    $connections->activate($org->id, $connection->id);

    $emitted = emittedOfType($events, 'connection.activated');

    expect($emitted)->toHaveCount(1)
        ->and($emitted[0]->organizationId)->toBe($org->id)
        ->and($emitted[0]->payload)->toBe(['id' => $connection->id, 'type' => 'oidc', 'provider' => null, 'name' => 'Acme Okta'])
        // Never the client secret, sealed or not.
        ->and(json_encode($emitted[0]->payload))->not->toContain('shh');

    $audit->assertRecorded('connection.activated');
});

it('does not announce an activation another organization was refused', function (): void {
    $events = $this->fakeEvents();
    $theirs = $this->makeOrganization('Theirs');
    $connection = app(Connections::class)->create($theirs->id, ConnectionType::Oidc, 'Theirs', [
        'issuer' => 'https://idp.theirs.test', 'client_id' => 'abc', 'client_secret' => 'shh',
    ]);

    app(Connections::class)->activate('org-someone-else', $connection->id);

    expect(emittedOfType($events, 'connection.activated'))->toBe([]);
});

it('emits the token-vault grant and revocation events without the credential', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization('Acme');
    $owner = VaultOwner::organization($org->id);
    $vault = app(SecretVault::class);

    $secret = $vault->store('openai', 'openai', 'sk-live-very-secret', $owner);
    $vault->grant($secret->id, 'agent-1', $owner, 120);
    $vault->revokeGrant($secret->id, 'agent-1', $owner);
    $vault->revoke($secret->id, $owner);

    expect(emittedOfType($events, 'vault.grant.created')[0]->payload)->toBe(['secret_id' => $secret->id, 'client_id' => 'agent-1', 'max_ttl_seconds' => 120])
        ->and(emittedOfType($events, 'vault.grant.revoked')[0]->payload)->toBe(['secret_id' => $secret->id, 'client_id' => 'agent-1'])
        ->and(emittedOfType($events, 'vault.secret.revoked')[0]->payload)->toBe(['secret_id' => $secret->id, 'provider' => 'openai']);

    foreach ($events->emitted as $event) {
        expect(json_encode($event->payload))->not->toContain('sk-live-very-secret');

        if (str_starts_with($event->type, 'vault.')) {
            // An organization's secret is announced to that organization's subscribers.
            expect($event->organizationId)->toBe($org->id);
        }
    }
});

it('emits governance.access.revoked when a closed review takes a grant away', function (): void {
    $events = $this->fakeEvents();
    $roles = app(Roles::class);
    $editor = $roles->define('acme', 'Editor');
    $roles->assign('acme', 'user-1', $editor->id);
    app(Memberships::class)->add('acme', 'owner-1', MembershipRole::Owner);
    app(Memberships::class)->add('acme', 'user-1', MembershipRole::Member);

    $reviews = app(AccessReviews::class);
    $campaign = $reviews->open('acme', 'Q3');
    $item = collect($reviews->itemsFor($campaign->id))
        ->first(fn ($item): bool => $item->subject_id === 'user-1' && $item->access_ref === $editor->id);

    foreach ($reviews->itemsFor($campaign->id) as $other) {
        if ($other->id !== $item->id) {
            $reviews->certify($other->id, 'reviewer', 'acme');
        }
    }

    $reviews->revoke($item->id, 'reviewer', 'acme', 'left the team');
    $reviews->close($campaign->id, 'acme');

    $emitted = emittedOfType($events, 'governance.access.revoked');

    expect($emitted)->toHaveCount(1)
        ->and($emitted[0]->organizationId)->toBe('acme')
        ->and($emitted[0]->payload)->toBe([
            'campaign_id' => $campaign->id,
            'user_id' => 'user-1',
            'access_type' => 'role',
            'access_ref' => $editor->id,
        ]);
});

it('emits the legacy organization.settings_updated beside organization.updated', function (): void {
    $events = $this->fakeEvents();
    $org = $this->makeOrganization('Acme');

    app(Organizations::class)->updateSettings($org->id, ['locale' => 'da']);

    $legacy = emittedOfType($events, 'organization.settings_updated');

    expect($legacy)->toHaveCount(1)
        ->and($legacy[0]->payload)->toBe(['id' => $org->id, 'keys' => ['locale']])
        ->and($legacy[0]->organizationId)->toBe($org->id)
        ->and(emittedOfType($events, 'organization.updated'))->toHaveCount(1);
});
