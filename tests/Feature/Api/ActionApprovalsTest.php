<?php

declare(strict_types=1);

use Cbox\Id\Kernel\Events\Testing\InteractsWithEvents;
use Cbox\Id\Kernel\Events\ValueObjects\DomainEvent;
use Cbox\Id\OAuthServer\Contracts\ActionApprovals;
use Cbox\Id\OAuthServer\Contracts\BackchannelAuthentication;
use Cbox\Id\OAuthServer\Enums\ActionApprovalStatus;
use Cbox\Id\OAuthServer\Exceptions\InvalidGrant;
use Cbox\Id\OAuthServer\Models\BackchannelAuthRequest;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class, InteractsWithEvents::class);

/*
| A person approving ONE action. The approval is bound to a digest of exactly that action
| and spent once; it is never a token.
*/

function approvalDigest(string $action = 'apps.secret.rotate:app_1'): string
{
    return hash('sha256', $action);
}

it('asks the person, and is answered on the same surface as a CIBA request', function (): void {
    $client = $this->makeClient(['openid'])->client;
    $user = $this->makeUser('ada@example.test');
    $approvals = app(ActionApprovals::class);

    $request = $approvals->request($client, $user->id, 'deploy-bot wants to rotate the secret of Billing · K7Q2', approvalDigest());

    expect($approvals->status($request->requestId))->toBe(ActionApprovalStatus::Pending)
        ->and($request->bindingMessage)->toContain('K7Q2');

    expect(app(BackchannelAuthentication::class)->approve($request->requestId, $user->id))->toBeTrue()
        ->and($approvals->status($request->requestId))->toBe(ActionApprovalStatus::Approved);
});

it('raises the CIBA event with an action purpose so the host can notify the person', function (): void {
    $events = $this->fakeEvents();
    $client = $this->makeClient(['openid'])->client;
    $user = $this->makeUser('bo@example.test');

    app(ActionApprovals::class)->request($client, $user->id, 'Approve the change', approvalDigest());

    $events->assertEmitted('oauth.backchannel_authentication_requested', fn (DomainEvent $event): bool => ($event->payload['purpose'] ?? null) === 'action');
});

it('is spent exactly once, and only for the action it approved', function (): void {
    $client = $this->makeClient(['openid'])->client;
    $user = $this->makeUser('cy@example.test');
    $approvals = app(ActionApprovals::class);

    $request = $approvals->request($client, $user->id, 'Approve the change', approvalDigest());
    app(BackchannelAuthentication::class)->approve($request->requestId, $user->id);

    expect($approvals->consume($request->requestId, approvalDigest('apps.secret.rotate:app_2')))->toBeFalse()
        ->and($approvals->consume($request->requestId, approvalDigest()))->toBeTrue()
        ->and($approvals->consume($request->requestId, approvalDigest()))->toBeFalse()
        ->and($approvals->status($request->requestId))->toBe(ActionApprovalStatus::Consumed);
});

it('cannot be spent before approval, after denial, or after it lapses', function (): void {
    $client = $this->makeClient(['openid'])->client;
    $user = $this->makeUser('di@example.test');
    $approvals = app(ActionApprovals::class);

    $pending = $approvals->request($client, $user->id, 'One', approvalDigest());
    expect($approvals->consume($pending->requestId, approvalDigest()))->toBeFalse();

    $denied = $approvals->request($client, $user->id, 'Two', approvalDigest());
    app(BackchannelAuthentication::class)->deny($denied->requestId, $user->id);
    expect($approvals->consume($denied->requestId, approvalDigest()))->toBeFalse()
        ->and($approvals->status($denied->requestId))->toBe(ActionApprovalStatus::Denied);

    $lapsed = $approvals->request($client, $user->id, 'Three', approvalDigest(), 60);
    app(BackchannelAuthentication::class)->approve($lapsed->requestId, $user->id);
    $this->travel(2)->minutes();
    expect($approvals->consume($lapsed->requestId, approvalDigest()))->toBeFalse()
        ->and($approvals->status($lapsed->requestId))->toBe(ActionApprovalStatus::Expired);
});

it('may only be approved by the person it was raised for', function (): void {
    $client = $this->makeClient(['openid'])->client;
    $ada = $this->makeUser('ada2@example.test');
    $eve = $this->makeUser('eve@example.test');

    $request = app(ActionApprovals::class)->request($client, $ada->id, 'Approve', approvalDigest());

    expect(app(BackchannelAuthentication::class)->approve($request->requestId, $eve->id))->toBeFalse();
})->group('security');

it('is never redeemable for tokens at the token endpoint', function (): void {
    $registered = $this->makeClient(['openid'], grantTypes: ['urn:openid:params:grant-type:ciba']);
    $user = $this->makeUser('fi@example.test');

    $request = app(ActionApprovals::class)->request($registered->client, $user->id, 'Approve', approvalDigest());
    app(BackchannelAuthentication::class)->approve($request->requestId, $user->id);

    // Give the row a handle we know, as if it had leaked.
    BackchannelAuthRequest::query()->whereKey($request->requestId)->update(['auth_req_id_hash' => hash('sha256', 'auth_req_known')]);

    app(BackchannelAuthentication::class)->redeem($registered->client->client_id, 'auth_req_known');
})->throws(InvalidGrant::class)->group('security');

it('refuses a missing or overlong binding message and a malformed digest', function (string $message, string $digest): void {
    $client = $this->makeClient(['openid'])->client;
    $user = $this->makeUser('gu@example.test');

    app(ActionApprovals::class)->request($client, $user->id, $message, $digest);
})->with([
    'empty message' => ['', hash('sha256', 'x')],
    'overlong message' => [str_repeat('a', 256), hash('sha256', 'x')],
    'not a digest' => ['Approve', 'rotate-the-secret'],
])->throws(InvalidArgumentException::class);
