<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SubjectEraser;
use Cbox\Id\Kernel\Events\Contracts\EventBus;
use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\OAuthServer\Contracts\TokenIssuer;
use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\UserProperties\Jobs\RelayPropertyChanges;
use Cbox\Id\UserProperties\Models\PropertyDocument;
use Cbox\Id\UserProperties\Testing\InteractsWithUserProperties;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\Webhooks\Contracts\WebhookDispatcher;
use Cbox\Id\Webhooks\Enums\DeliveryStatus;
use Cbox\Id\Webhooks\Models\WebhookDelivery;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;

uses(RefreshDatabase::class, InteractsWithUserProperties::class);

beforeEach(function (): void {
    $this->appClient = $this->makeClient(['user_properties:read', 'user_properties:write'])->client;
    $this->otherClient = $this->makeClient(['user_properties:read', 'user_properties:write'])->client;
    $this->person = $this->makeUser();
    $this->properties = app(UserProperties::class);
    $this->makePropertyNamespace('preferences', [$this->appClient->client_id, $this->otherClient->client_id], [$this->appClient->client_id]);
    $this->makePropertyNamespace('private', [$this->appClient->client_id], [$this->appClient->client_id]);
});

it('shares preferences while refusing ungranted namespace access and read-only writes', function (): void {
    $this->properties->patch($this->appClient->client_id, $this->person->id, 'preferences', new PropertyPatch(0, (object) ['theme' => 'dark', 'language' => 'da', 'timezone' => 'Europe/Copenhagen']));
    expect($this->properties->read($this->otherClient->client_id, $this->person->id, 'preferences')->data->theme)->toBe('dark');
    expect(fn () => $this->properties->read($this->otherClient->client_id, $this->person->id, 'private'))->toThrow(AuthorizationException::class);
    expect(fn () => $this->properties->patch($this->otherClient->client_id, $this->person->id, 'preferences', new PropertyPatch(1, (object) ['theme' => 'light'])))->toThrow(AuthorizationException::class);
});

it('patches keys atomically, preserves null and JSON shapes, detects conflicts and suppresses no-op events', function (): void {
    $client = $this->appClient->client_id;
    $user = $this->person->id;
    $this->properties->patch($client, $user, 'private', new PropertyPatch(0, (object) ['first' => null, 'nested' => (object) [], 'list' => []]));
    $this->properties->patch($client, $user, 'private', new PropertyPatch(1, (object) ['second' => 7]));
    expect(fn () => $this->properties->patch($client, $user, 'private', new PropertyPatch(1, (object) ['second' => 8])))->toThrow(ConflictHttpException::class);
    $result = $this->properties->patch($client, $user, 'private', new PropertyPatch(2, remove: ['second']));
    expect($result->version)->toBe(3)->and($result->data)->toEqual((object) ['first' => null, 'nested' => (object) [], 'list' => []])
        ->and($result->data->nested)->toBeInstanceOf(stdClass::class)->and($result->data->list)->toBe([]);
    $this->properties->patch($client, $user, 'private', new PropertyPatch(3, (object) ['first' => null]));
    expect(Event::query()->where('type', 'user.metadata.updated')->count())->toBe(3);
    expect(Event::query()->where('type', 'user.metadata.updated')->first()->payload)->not->toHaveKey('data');
});

it('rolls back the document and its event together', function (): void {
    DB::beginTransaction();
    $this->properties->patch($this->appClient->client_id, $this->person->id, 'preferences', new PropertyPatch(0, (object) ['theme' => 'dark']));
    DB::rollBack();
    expect(PropertyDocument::query()->count())->toBe(0)->and(Event::query()->where('type', 'user.preferences.updated')->count())->toBe(0);
});

it('validates built-in preferences and bounds custom data', function (): void {
    foreach ([(object) ['theme' => 'sepia'], (object) ['timezone' => 'Mars/Base'], (object) ['anything' => true], (object) ['theme' => null]] as $set) {
        expect(fn () => $this->properties->patch($this->appClient->client_id, $this->person->id, 'preferences', new PropertyPatch(0, $set)))->toThrow(ValidationException::class);
    }
    expect(fn () => new PropertyPatch(0, (object) ['large' => str_repeat('x', 16384)]))->toThrow(ValidationException::class);
    expect(fn () => new PropertyPatch(0, (object) ['theme' => 'dark'], ['theme']))->toThrow(ValidationException::class);
});

it('isolates the same namespace across environments', function (): void {
    $this->actingAsEnvironment('another-environment');
    expect(fn () => $this->properties->read($this->appClient->client_id, $this->person->id, 'preferences'))->toThrow(AuthorizationException::class);
});

it('delivers only to granted endpoints and rechecks grants before queued delivery', function (): void {
    Queue::fake();
    Http::fake();
    $allowed = $this->registerWebhook(null, 'https://example.com/hooks/allowed', ['*'])->endpoint;
    $denied = $this->registerWebhook(null, 'https://example.com/hooks/denied', ['*'])->endpoint;
    $client = $this->appClient->client_id;
    $this->makePropertyNamespace('private', [$client], [$client], [$allowed->id => $client]);
    $this->properties->patch($client, $this->person->id, 'private', new PropertyPatch(0, (object) ['secret' => 'value']));
    app(EventBus::class)->flushPending();
    $delivery = WebhookDelivery::query()->where('event_type', 'user.metadata.updated')->sole();
    expect($delivery->endpoint_id)->toBe($allowed->id)->not->toBe($denied->id);
    $this->makePropertyNamespace('private', [$client], [$client]);
    app(WebhookDispatcher::class)->deliver($delivery->id);
    expect($delivery->fresh()->status)->toBe(DeliveryStatus::Exhausted);
    Http::assertNothingSent();
});

it('serves the real authenticated API and restricts delegated tokens to their user', function (): void {
    $issuer = app(TokenIssuer::class);
    $token = $issuer->issueForUser($this->appClient, $this->person->id, null, ['user_properties:read', 'user_properties:write']);
    $url = '/oauth/users/'.$this->person->id.'/properties/preferences';
    $this->withToken($token->token)->getJson($url)->assertOk()->assertJsonPath('version', 0)->assertHeader('Cache-Control', 'no-store, private');
    $this->withToken($token->token)->patchJson($url, ['version' => 0, 'set' => ['theme' => 'dark']])->assertOk()->assertJsonPath('data.theme', 'dark');
    $this->withToken($token->token)->patchJson($url, ['version' => 0, 'set' => ['theme' => 'light']])->assertConflict();
    $other = $this->makeUser();
    $this->withToken($token->token)->getJson('/oauth/users/'.$other->id.'/properties/preferences')->assertForbidden();
});

it('rejects missing scope, wrong audience and missing DPoP proof', function (): void {
    $issuer = app(TokenIssuer::class);
    $url = '/oauth/users/'.$this->person->id.'/properties/preferences';
    $noScopeClient = $this->makeClient(['profile'])->client;
    $noScope = $issuer->issueForUser($noScopeClient, $this->person->id, null, ['profile']);
    $this->withToken($noScope->token)->getJson($url)->assertForbidden();
    $dpop = $issuer->issueForUser($this->appClient, $this->person->id, null, ['user_properties:read'], dpopJkt: 'proof-thumbprint');
    $this->withToken($dpop->token)->getJson($url)->assertUnauthorized();
});

it('accepts machine tokens only within explicit namespace grants', function (): void {
    $token = app(TokenIssuer::class)->issueClientCredentials($this->appClient, ['user_properties:read', 'user_properties:write']);
    $this->withToken($token->token)->getJson('/oauth/users/'.$this->person->id.'/properties/private')->assertOk();
    $token = app(TokenIssuer::class)->issueClientCredentials($this->otherClient, ['user_properties:read']);
    $this->withToken($token->token)->getJson('/oauth/users/'.$this->person->id.'/properties/private')->assertForbidden();
});

it('removes properties with user erasure and never delivers their pending changes afterwards', function (): void {
    Queue::fake();
    $client = $this->appClient->client_id;
    $endpoint = $this->registerWebhook(null, 'https://example.com/hooks/erase', ['user.metadata.updated'])->endpoint;
    $this->makePropertyNamespace('private', [$client], [$client], [$endpoint->id => $client]);
    $this->properties->patch($client, $this->person->id, 'private', new PropertyPatch(0, (object) ['personal' => 'private value']));
    app(SubjectEraser::class)->erase($this->person->id);
    expect(PropertyDocument::query()->count())->toBe(0);
    app(EventBus::class)->flushPending();
    expect(WebhookDelivery::query()->where('event_type', 'user.metadata.updated')->count())->toBe(0);
});

it('wakes the outbox on the queue after commit', function (): void {
    Queue::fake();
    $this->properties->patch($this->appClient->client_id, $this->person->id, 'preferences', new PropertyPatch(0, (object) ['theme' => 'dark']));
    Queue::assertPushed(RelayPropertyChanges::class, fn ($job) => $job->afterCommit === true);
    $events = $this->fakeEvents();
    (new RelayPropertyChanges)->handle($events);
});

it('rejects resource-audienced tokens and malformed HTTP patches', function (): void {
    $this->makeApi('https://resource.example.test', ['documents:read']);
    $this->appClient->scopes = ['user_properties:read', 'user_properties:write', 'documents:read'];
    $this->appClient->save();
    $token = app(TokenIssuer::class)->issueForUser($this->appClient, $this->person->id, null, ['user_properties:read', 'documents:read'], resource: 'https://resource.example.test');
    $url = '/oauth/users/'.$this->person->id.'/properties/preferences';
    $this->withToken($token->token)->getJson($url)->assertUnauthorized();
    $token = app(TokenIssuer::class)->issueForUser($this->appClient, $this->person->id, null, ['user_properties:write']);
    foreach ([['version' => 0, 'set' => ['light']], ['version' => -1], ['version' => 0, 'extra' => true], ['version' => 0, 'remove' => ['key' => 'theme']]] as $body) {
        $this->withToken($token->token)->patchJson($url, $body)->assertUnprocessable();
    }
});

it('does not allow a grant to bridge environment or organization ownership', function (): void {
    $other = $this->makeClient(organizationId: 'org_private')->client;
    expect(fn () => $this->makePropertyNamespace('leak', [$other->client_id]))->toThrow(ValidationException::class);
    $this->actingAsEnvironment('another-environment');
    expect(fn () => $this->makePropertyNamespace('leak', [$this->appClient->client_id]))->toThrow(ValidationException::class);
});

it('ignores nested object key order while retaining array order and value types', function (): void {
    $client = $this->appClient->client_id;
    $user = $this->person->id;
    $initial = (object) ['nested' => (object) ['longer' => true, 'x' => 1], 'items' => [1, 2]];
    $this->properties->patch($client, $user, 'private', new PropertyPatch(0, (object) ['custom' => $initial]));
    $reordered = (object) ['items' => [1, 2], 'nested' => (object) ['x' => 1, 'longer' => true]];
    expect($this->properties->patch($client, $user, 'private', new PropertyPatch(1, (object) ['custom' => $reordered]))->version)->toBe(1);
    $reordered->items = [2, 1];
    expect($this->properties->patch($client, $user, 'private', new PropertyPatch(1, (object) ['custom' => $reordered]))->version)->toBe(2);
    $reordered->nested->x = '1';
    expect($this->properties->patch($client, $user, 'private', new PropertyPatch(2, (object) ['custom' => $reordered]))->version)->toBe(3);
    expect(Event::query()->where('type', 'user.metadata.updated')->count())->toBe(3);
});
