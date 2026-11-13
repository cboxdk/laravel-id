<?php

declare(strict_types=1);

use Cbox\Id\Api\Authorization\ConfiguredResourceIntrospectionAccess;
use Cbox\Id\OAuthServer\Contracts\TokenIntrospector;
use Cbox\Id\OAuthServer\ValueObjects\Introspection;
use Cbox\Id\UserProperties\Http\PropertyTokenAccess;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

uses(RefreshDatabase::class);

/*
 * A machine token is an app acting as itself (client_credentials): active, its subject is
 * its client id, and nobody acts for anybody. Every token an app holds carries that app's
 * `client_id`, so `client_id` alone never says the caller IS the app — a person's token
 * through the same app, or a token somebody acts on (`act`), must not pass for it.
 */

it('tells a machine token from a person token', function (Introspection $token, bool $machine): void {
    expect($token->isMachine())->toBe($machine);
})->with([
    'client credentials' => [Introspection::active('cid_app', 'cid_app', [], []), true],
    'a person through the app' => [Introspection::active('user_ada', 'cid_app', [], []), false],
    'acted on by someone' => [Introspection::active('cid_app', 'cid_app', [], ['act' => ['sub' => 'user_agent']]), false],
    'an empty act claim' => [Introspection::active('cid_app', 'cid_app', [], ['act' => null]), false],
    'no client' => [Introspection::active('cid_app', null, [], []), false],
    'no subject' => [Introspection::active(null, 'cid_app', [], []), false],
    'empty subject and client' => [Introspection::active('', '', [], []), false],
    'inactive' => [Introspection::inactive(), false],
]);

/** Answer every bearer with $token. */
function introspectAs(Introspection $token): void
{
    app()->instance(TokenIntrospector::class, new readonly class($token) implements TokenIntrospector
    {
        public function __construct(private Introspection $token) {}

        public function introspect(string $token): Introspection
        {
            return $this->token;
        }

        public function revoke(string $jti): void {}
    });
}

function propertiesRequest(): Request
{
    return Request::create('/user-properties', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer opaque']);
}

it('lets only a machine token reach another person\'s properties', function (): void {
    introspectAs(Introspection::active('cid_app', 'cid_app', ['user_properties:read'], []));

    expect(app(PropertyTokenAccess::class)->client(propertiesRequest(), 'user_ada'))->toBe('cid_app');
});

it('keeps a token somebody acts on to its own subject', function (): void {
    introspectAs(Introspection::active('cid_app', 'cid_app', ['user_properties:read'], ['act' => ['sub' => 'user_agent']]));

    expect(fn () => app(PropertyTokenAccess::class)->client(propertiesRequest(), 'user_ada'))
        ->toThrow(AccessDeniedHttpException::class);
})->group('security');

it('keeps a person token to its own subject', function (): void {
    introspectAs(Introspection::active('user_ada', 'cid_app', ['user_properties:read'], []));

    expect(app(PropertyTokenAccess::class)->client(propertiesRequest(), 'user_ada'))->toBe('cid_app')
        ->and(fn () => app(PropertyTokenAccess::class)->client(propertiesRequest(), 'user_bob'))
        ->toThrow(AccessDeniedHttpException::class);
})->group('security');

it('asks for membership unless a resource server is looking at a machine token', function (): void {
    $resource = 'https://domains.example.test/api';
    $server = $this->makeClient()->client;
    $org = $this->makeOrganization();
    config(['cbox-id.oauth.introspection.resource_servers' => [$server->client_id => [$resource]]]);
    $access = app(ConfiguredResourceIntrospectionAccess::class);
    $claims = ['aud' => $resource, 'org' => $org->id];

    // The app's own token has no membership to check.
    expect($access->allows($server, Introspection::active('cid_app', 'cid_app', [], $claims)))->toBeTrue()
        // One somebody acts on is not the app's own, and nobody here is a member.
        ->and($access->allows($server, Introspection::active('cid_app', 'cid_app', [], [...$claims, 'act' => ['sub' => 'user_agent']])))->toBeFalse()
        ->and($access->allows($server, Introspection::active('user_ada', 'cid_app', [], $claims)))->toBeFalse();
})->group('security');
