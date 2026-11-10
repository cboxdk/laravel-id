<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Cbox\Id\Webhooks\Support\WebhookEventNames;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

beforeEach(fn () => config(['cbox-id.webhooks.verify_url' => false]));

/** The `type` of the one delivery sent. */
function sentEventType(): string
{
    $types = Http::recorded()->map(fn (array $pair): string => (string) json_decode($pair[0]->body(), true)['type']);

    expect($types)->toHaveCount(1);

    return $types->first();
}

it('maps every catalogued event to an id.* name and back', function (WebhookEventType $type): void {
    $prefixed = WebhookEventNames::prefixed($type->value);

    expect($prefixed)->toStartWith('id.')
        ->and(WebhookEventNames::internal($prefixed))->toBe($type->value)
        ->and(WebhookEventNames::prefixed($prefixed))->toBe($prefixed)
        ->and(WebhookEventNames::internal($type->value))->toBe($type->value);
})->with(WebhookEventType::cases());

it('names the pairs the standard calls out', function (): void {
    expect(WebhookEventNames::prefixed('organization.member_added'))->toBe('id.organization.member_added')
        ->and(WebhookEventNames::prefixed('user.login'))->toBe('id.user.signed_in')
        ->and(WebhookEventNames::internal('id.user.signed_in'))->toBe('user.login')
        ->and(WebhookEventNames::prefixed(WebhookEventType::WILDCARD))->toBe(WebhookEventType::WILDCARD);
});

it('keeps sending today\'s names by default', function (): void {
    expect(config('cbox-id.webhooks.prefixed_event_types'))->toBeFalse();

    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['user.login']);

    app(WebhookDispatcher::class)->dispatch('user.login', ['user_id' => 'u1'], 'org_a');

    expect(sentEventType())->toBe('user.login');
});

it('sends id.* names once the operator turns them on', function (): void {
    config(['cbox-id.webhooks.prefixed_event_types' => true]);

    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/x', ['organization.member_added']);

    app(WebhookDispatcher::class)->dispatch('organization.member_added', ['user_id' => 'u1'], 'org_a');

    expect(sentEventType())->toBe('id.organization.member_added');
});

it('reads the switch from an env string', function (): void {
    config(['cbox-id.webhooks.prefixed_event_types' => 'true']);

    expect(WebhookEventNames::onTheWire('user.login'))->toBe('id.user.signed_in');

    config(['cbox-id.webhooks.prefixed_event_types' => 'false']);

    expect(WebhookEventNames::onTheWire('user.login'))->toBe('user.login');
});

it('matches a subscription made with either name', function (bool $prefixedOnTheWire): void {
    config(['cbox-id.webhooks.prefixed_event_types' => $prefixedOnTheWire]);

    Http::fake(['*' => Http::response('', 200)]);
    $this->registerWebhook('org_a', 'https://hook.test/new', ['id.user.signed_in']);
    $this->registerWebhook('org_a', 'https://hook.test/old', ['user.login']);

    app(WebhookDispatcher::class)->dispatch('user.login', [], 'org_a');

    Http::assertSentCount(2);
    Http::assertSent(fn (Request $request): bool => json_decode($request->body(), true)['type'] === ($prefixedOnTheWire ? 'id.user.signed_in' : 'user.login'));

    expect(WebhookEventType::subscribable('id.user.signed_in'))->toBeTrue()
        ->and(WebhookEventType::subscribable('id.organization.member_added'))->toBeTrue();
})->with([false, true]);
