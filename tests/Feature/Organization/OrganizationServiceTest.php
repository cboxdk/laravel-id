<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Tenancy\Contracts\Tenant;
use Cbox\Id\Organization\Contracts\Organizations;
use Cbox\Id\Organization\Exceptions\SlugAlreadyTaken;
use Cbox\Id\Organization\ValueObjects\NewOrganization;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('creates, finds and looks up an organization by slug', function (): void {
    $service = app(Organizations::class);
    $org = $service->create(new NewOrganization('Northwind Traders', 'northwind'));

    expect($org->slug)->toBe('northwind')
        ->and($service->find($org->id)?->id)->toBe($org->id)
        ->and($service->bySlug('northwind')?->id)->toBe($org->id);
});

it('rejects a duplicate slug', function (): void {
    app(Organizations::class)->create(new NewOrganization('A', 'dup'));

    expect(fn () => app(Organizations::class)->create(new NewOrganization('B', 'dup')))
        ->toThrow(SlugAlreadyTaken::class);
});

it('is a Tenant whose key is its id', function (): void {
    $org = $this->makeOrganization();

    expect($org)->toBeInstanceOf(Tenant::class)
        ->and($org->tenantKey())->toBe($org->id);
});

it('emits an event and records audit on creation', function (): void {
    $events = $this->fakeEvents();
    $audit = $this->fakeAudit();

    $this->makeOrganization('Acme');

    $events->assertEmitted('organization.created');
    $audit->assertRecorded('organization.created');
});

it('merges and persists organization settings', function (): void {
    $org = $this->makeOrganization();
    $orgs = app(Organizations::class);

    $orgs->updateSettings($org->id, ['brand_color' => '#0ea5e9']);
    $orgs->updateSettings($org->id, ['brand_logo_url' => 'https://x/logo.png']);

    $fresh = $orgs->find($org->id);
    expect($fresh?->settings)->toMatchArray([
        'brand_color' => '#0ea5e9',
        'brand_logo_url' => 'https://x/logo.png',
    ]);
});
