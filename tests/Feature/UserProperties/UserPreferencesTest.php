<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Models\Event;
use Cbox\Id\UserProperties\Contracts\UserPreferences;
use Cbox\Id\UserProperties\Contracts\UserProperties;
use Cbox\Id\UserProperties\Models\PropertyNamespace;
use Cbox\Id\UserProperties\Testing\InteractsWithUserProperties;
use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

uses(RefreshDatabase::class, InteractsWithUserProperties::class);

it('stores subject preferences without granting OAuth clients access', function (): void {
    $person = $this->makeUser();
    $client = $this->makeClient(['user_properties:read', 'user_properties:write'])->client;
    $preferences = app(UserPreferences::class);
    expect($preferences->read($person->id)->version)->toBe(0);
    $saved = $preferences->patch($person->id, new PropertyPatch(0, (object) ['language' => 'da']));
    expect($saved->data->language)->toBe('da')->and($saved->version)->toBe(1);
    $namespace = PropertyNamespace::query()->where('name', 'preferences')->firstOrFail();
    expect($namespace->readers)->toBe([])->and($namespace->writers)->toBe([]);
    expect(fn () => app(UserProperties::class)->read($client->client_id, $person->id, 'preferences'))->toThrow(AuthorizationException::class);
    expect(Event::query()->where('type', 'user.preferences.updated')->firstOrFail()->payload)
        ->toHaveKey('client_id', null)->not->toHaveKey('data');
});

it('shares versions and preserves unrelated preferences across host and granted apps', function (): void {
    $person = $this->makeUser();
    $client = $this->makeClient(['user_properties:read', 'user_properties:write'])->client;
    $this->makePropertyNamespace('preferences', [$client->client_id], [$client->client_id]);
    $properties = app(UserProperties::class);
    $preferences = app(UserPreferences::class);
    $properties->patch($client->client_id, $person->id, 'preferences', new PropertyPatch(0, (object) ['theme' => 'dark']));
    expect(fn () => $preferences->patch($person->id, new PropertyPatch(0, (object) ['language' => 'da'])))->toThrow(ConflictHttpException::class);
    $preferences->patch($person->id, new PropertyPatch(1, (object) ['language' => 'da']));
    $shared = $properties->read($client->client_id, $person->id, 'preferences');
    expect($shared->data)->toEqual((object) ['theme' => 'dark', 'language' => 'da'])->and($shared->version)->toBe(2);
    $preferences->patch($person->id, new PropertyPatch(2, (object) ['language' => 'da']));
    expect(Event::query()->where('type', 'user.preferences.updated')->count())->toBe(2);
    expect(fn () => $preferences->patch($person->id, new PropertyPatch(2, (object) ['password' => 'secret'])))->toThrow(ValidationException::class);
});

it('refuses a subject from another environment without creating namespace grants', function (): void {
    $person = $this->makeUser();
    app(UserPreferences::class)->patch($person->id, new PropertyPatch(0, (object) ['language' => 'da']));
    $this->actingAsEnvironment('another-environment');
    expect(fn () => app(UserPreferences::class)->read($person->id))->toThrow(NotFoundHttpException::class);
    expect(fn () => app(UserPreferences::class)->patch($person->id, new PropertyPatch(0, (object) ['language' => 'fr'])))->toThrow(NotFoundHttpException::class);
    expect(PropertyNamespace::query()->count())->toBe(0);
});
