<?php

declare(strict_types=1);

use Cbox\Id\Identity\Contracts\SessionManager;
use Illuminate\Auth\GenericUser;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('does not revoke authenticated sessions without a signed logout message', function (string $method, array $payload): void {
    $subject = $this->makeUser('logout-csrf@example.test');
    $sessions = app(SessionManager::class);
    $first = $sessions->start($subject->id, null, ['pwd']);
    $second = $sessions->start($subject->id, null, ['pwd']);

    $this->actingAs(new GenericUser(['id' => $subject->id, 'remember_token' => '']))
        ->call($method, '/sso/saml/idp/slo', $payload)
        ->assertStatus(400);

    expect($sessions->active($first->id))->not->toBeNull()
        ->and($sessions->active($second->id))->not->toBeNull();
})->with([
    'bare GET' => ['GET', []],
    'bare POST' => ['POST', []],
    'empty message' => ['POST', ['SAMLRequest' => '']],
    'non-string message' => ['POST', ['SAMLRequest' => ['invalid']]],
]);
