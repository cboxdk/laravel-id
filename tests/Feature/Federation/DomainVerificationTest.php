<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Exceptions\DomainAlreadyClaimed;
use Cbox\Id\Federation\Exceptions\DomainNotVerified;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * Pest ignores a file-level `@group` docblock — membership comes only from a `uses()` or
 * a per-test `->group()`. So the 17 files that declared the group this way contributed
 * ZERO tests to `--group=isolation`, including the environment-isolation proof itself,
 * while docs/core-concepts/environments.md tells operators to run exactly that command
 * as the evidence. A selector that silently omits its own load-bearing file is worse than
 * no selector.
 */
uses()->group('isolation');

it('adds a domain unverified with a DNS challenge', function (): void {
    $org = $this->makeOrganization('Acme');
    $domains = app(DomainVerification::class);

    $domain = $domains->add($org->id, 'Acme.com');

    expect($domain->domain)->toBe('acme.com')                      // normalized
        ->and($domain->isVerified())->toBeFalse()
        ->and($domain->verification_token)->not->toBe('')
        ->and($domains->challengeHost('acme.com'))->toBe('_cbox-id-challenge.acme.com');
});

it('verifies only when the TXT challenge is published (deny-by-default)', function (): void {
    $org = $this->makeOrganization('Acme');
    $dns = $this->fakeDns();
    $domains = app(DomainVerification::class);
    $domain = $domains->add($org->id, 'acme.com');

    // No record yet → refused.
    expect($domains->verify($domain->id))->toBeFalse()
        ->and($domains->forEmail('jane@acme.com'))->toBeNull();

    $dns->publish($domains->challengeHost('acme.com'), $domain->verification_token);

    expect($domains->verify($domain->id))->toBeTrue()
        ->and($domains->forEmail('jane@acme.com')?->id)->toBe($domain->id)
        ->and($domains->forEmail('jane@other.com'))->toBeNull();
});

it('routes a verified-domain email to the org active connection (home-realm discovery)', function (): void {
    $org = $this->makeOrganization('Acme');
    $connection = $this->makeConnection($org->id);           // active by default
    $this->makeVerifiedDomain($org->id, 'acme.com');

    $resolved = app(DomainVerification::class)->connectionForEmail('jane@acme.com');

    expect($resolved?->id)->toBe($connection->id)
        ->and(app(DomainVerification::class)->connectionForEmail('nobody@acme.com')?->id)->toBe($connection->id)
        ->and(app(DomainVerification::class)->connectionForEmail('jane@unverified.com'))->toBeNull();
});

it('toggles the optional capture gate', function (): void {
    $org = $this->makeOrganization('Acme');
    $domain = $this->makeVerifiedDomain($org->id, 'acme.com');

    expect($domain->capture)->toBeFalse();

    app(DomainVerification::class)->setCapture($domain->id, true);

    expect(app(DomainVerification::class)->forEmail('jane@acme.com')?->capture)->toBeTrue();
});

/**
 * Capture takes every sign-in on an email domain and routes it to one organization's
 * identity provider. On an UNVERIFIED domain that is one tenant claiming another's
 * addresses — the DNS challenge is the only thing standing between the two.
 *
 * The rule lived in the callers, and the callers disagreed: one console refused an
 * unverified domain, the other did not, so the weaker one decided. Anything reaching
 * this service — a console, an API request, a script — now gets the same answer.
 */
it('refuses to capture a domain nobody has proved they own', function (): void {
    $org = $this->makeOrganization('Acme');
    $domain = app(DomainVerification::class)->add($org->id, 'acme.com');

    expect(fn () => app(DomainVerification::class)->setCapture($domain->id, true))
        ->toThrow(DomainNotVerified::class);

    expect($domain->fresh()?->capture)->toBeFalse();
});

it('always allows capture to be switched off', function (): void {
    $org = $this->makeOrganization('Acme');
    $domain = $this->makeVerifiedDomain($org->id, 'acme.com');
    app(DomainVerification::class)->setCapture($domain->id, true);

    // Withdrawing a claim can only ever be safe, verified or not.
    app(DomainVerification::class)->setCapture($domain->id, false);

    expect($domain->fresh()?->capture)->toBeFalse();
});

it('refuses a domain another organization has verified', function (): void {
    $acme = $this->makeOrganization('Acme');
    $evil = $this->makeOrganization('Evil');
    $this->makeVerifiedDomain($acme->id, 'acme.com');

    expect(fn () => app(DomainVerification::class)->add($evil->id, 'acme.com'))
        ->toThrow(DomainAlreadyClaimed::class);
});

/**
 * WHOEVER PROVES IT FIRST, NOT WHOEVER TYPES IT FIRST. Any row for a domain used to refuse
 * every other organization, verified or not, so anybody able to add a domain for their own
 * organization could squat another's with no DNS control at all: the real owner was refused
 * and never got a challenge to publish.
 */
it('gives the real owner its own challenge when another organization only claimed the domain', function (): void {
    $squatter = $this->makeOrganization('Squatter');
    $owner = $this->makeOrganization('Owner');
    $dns = $this->fakeDns();
    $domains = app(DomainVerification::class);

    $squat = $domains->add($squatter->id, 'victim.example');
    $claim = $domains->add($owner->id, 'VICTIM.example');

    expect($claim->organization_id)->toBe($owner->id)
        ->and($claim->id)->not->toBe($squat->id)
        ->and($claim->verification_token)->not->toBe($squat->verification_token);

    $dns->publish($domains->challengeHost('victim.example'), $claim->verification_token);

    expect($domains->verify($claim->id))->toBeTrue()
        ->and($domains->verify($squat->id))->toBeFalse()
        ->and($domains->forEmail('ceo@victim.example')?->organization_id)->toBe($owner->id);
});

it('lets only one organization verify a domain, even with both challenges published', function (): void {
    $first = $this->makeOrganization('First');
    $second = $this->makeOrganization('Second');
    $dns = $this->fakeDns();
    $domains = app(DomainVerification::class);

    $a = $domains->add($first->id, 'shared.example');
    $b = $domains->add($second->id, 'shared.example');
    $dns->publish($domains->challengeHost('shared.example'), $a->verification_token);
    $dns->publish($domains->challengeHost('shared.example'), $b->verification_token);

    expect($domains->verify($a->id))->toBeTrue()
        ->and($domains->verify($b->id))->toBeFalse()
        ->and($b->fresh()?->isVerified())->toBeFalse();
});

it('is idempotent for the organization that already claimed the domain', function (): void {
    $acme = $this->makeOrganization('Acme');
    $domains = app(DomainVerification::class);

    expect($domains->add($acme->id, 'acme.com')->id)->toBe($domains->add($acme->id, 'ACME.com')->id);
});

/**
 * @group isolation
 */
it('does not route a domain verified in another environment', function (): void {
    $org = $this->runAsEnvironment('env_a', function () {
        $o = $this->makeOrganization('Acme');
        $this->makeVerifiedDomain($o->id, 'acme.com');

        return $o;
    });

    $fromB = $this->runAsEnvironment('env_b', fn () => app(DomainVerification::class)->forEmail('jane@acme.com'));

    expect($fromB)->toBeNull();
});
