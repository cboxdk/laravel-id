<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\Webhooks\Contracts\WebhookRegistry;
use Cbox\Id\Webhooks\Models\WebhookEndpoint;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config()->set('cbox-id.webhooks.verify_url', false);
    config()->set('cbox-id.external_actions.verify_url', false);
});

/*
 * Reach beyond one tenant is a DIFFERENT CALL, not a different argument.
 *
 * Both registries once took the owning organization as a nullable parameter, and null
 * meant "every organization in this environment" — a webhook endpoint fed every tenant's
 * members joining, sign-ins failing and roles changing; an external action consulted at
 * `token_minting` able to refuse issuance for all of them. External actions went further
 * and DEFAULTED that argument to null, so a caller who simply forgot the third argument
 * got the widest scope the platform has.
 *
 * These tests pin the shape rather than a message: `register()` cannot express
 * environment-wide coverage at all, because its parameter is a non-nullable string, and
 * the only way to reach it is a method whose name says so. That is what makes the
 * platform-wide callers greppable — and there is exactly one of each, on the environment
 * plane of the console.
 */
it('cannot express environment-wide webhook coverage through register()', function (): void {
    $method = new ReflectionMethod(WebhookRegistry::class, 'register');
    $organizationId = $method->getParameters()[0];

    expect($organizationId->getName())->toBe('organizationId')
        ->and($organizationId->allowsNull())->toBeFalse()
        ->and($organizationId->isOptional())->toBeFalse();
})->group('security');

it('cannot express environment-wide hook coverage through register()', function (): void {
    $method = new ReflectionMethod(ExternalActions::class, 'register');
    $organizationId = $method->getParameters()[2];

    expect($organizationId->getName())->toBe('organizationId')
        ->and($organizationId->allowsNull())->toBeFalse()
        // The one that mattered: it used to default to null, so a caller who left it off
        // registered a hook for every tenant rather than for none.
        ->and($organizationId->isOptional())->toBeFalse();
})->group('security');

it('keeps a webhook registered for an organization owned by that organization', function (): void {
    $registered = app(WebhookRegistry::class)->register('org_a', 'https://hooks.a.test', ['user.created']);

    expect(WebhookEndpoint::query()->whereKey($registered->endpoint->id)->value('organization_id'))
        ->toBe('org_a');
})->group('security');

it('registers environment-wide webhook coverage only when asked for by name', function (): void {
    $registered = app(WebhookRegistry::class)->registerForEnvironment('https://hooks.env.test', ['user.created']);

    expect(WebhookEndpoint::query()->whereKey($registered->endpoint->id)->value('organization_id'))
        ->toBeNull();
})->group('security');

it('keeps a hook registered for an organization owned by that organization', function (): void {
    $registered = app(ExternalActions::class)->register(HookPoint::TokenMinting, 'https://hook.a.test', 'org_a');

    expect(ExternalActionEndpoint::query()->whereKey($registered->endpoint->id)->value('organization_id'))
        ->toBe('org_a');
})->group('security');

it('registers environment-wide hook coverage only when asked for by name', function (): void {
    $registered = app(ExternalActions::class)->registerForEnvironment(HookPoint::TokenMinting, 'https://hook.env.test');

    expect(ExternalActionEndpoint::query()->whereKey($registered->endpoint->id)->value('organization_id'))
        ->toBeNull();
})->group('security');
