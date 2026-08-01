<?php

declare(strict_types=1);

use Cbox\Id\Federation\Contracts\DomainVerification;
use Cbox\Id\Federation\Exceptions\DomainAlreadyClaimed;
use Cbox\Id\Federation\Exceptions\DomainNotVerified;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

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

it('refuses a domain already claimed by another organization', function (): void {
    $acme = $this->makeOrganization('Acme');
    $evil = $this->makeOrganization('Evil');
    app(DomainVerification::class)->add($acme->id, 'acme.com');

    expect(fn () => app(DomainVerification::class)->add($evil->id, 'acme.com'))
        ->toThrow(DomainAlreadyClaimed::class);
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
