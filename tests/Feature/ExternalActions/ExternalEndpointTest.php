<?php

declare(strict_types=1);

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\Exceptions\UnsafeActionUrl;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\Kernel\Crypto\Contracts\SecretBox;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('registers an endpoint, sealing the signing secret and revealing it once', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);

    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test/token');

    expect($registered->secret)->toMatch('/^[0-9a-f]{64}$/');

    $stored = ExternalActionEndpoint::query()->whereKey($registered->endpoint->id)->firstOrFail();
    expect($stored->secret_encrypted)->not->toContain($registered->secret)
        ->and(app(SecretBox::class)->open($stored->secret_encrypted, $stored->secretContext()))->toBe($registered->secret);
});

it('refuses to register an endpoint at an SSRF-unsafe URL', function (): void {
    // verify_url is on (default); a cloud-metadata address is blocked.
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'http://169.254.169.254/latest/meta-data/');
})->throws(UnsafeActionUrl::class);

it('runs a registered endpoint through the pipeline and folds its enrichment', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    $transport = $this->fakeActionTransport()->willEnrich(['region' => 'eu']);
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    $outcome = app(ActionPipeline::class)->run(HookPoint::TokenMinting, new ActionContext(HookPoint::TokenMinting, ['client_id' => 'c1']));

    $transport->assertSent();
    expect($outcome->allowed)->toBeTrue()
        ->and($outcome->enrichment)->toBe(['region' => 'eu']);
});

it('vetoes when a registered endpoint denies', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    $this->fakeActionTransport()->willDeny('blocked by external policy');
    $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');

    $outcome = app(ActionPipeline::class)->run(HookPoint::TokenMinting, new ActionContext(HookPoint::TokenMinting, []));

    expect($outcome->allowed)->toBeFalse()
        ->and($outcome->reason)->toBe('blocked by external policy');
});

it('does not call a paused endpoint', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);
    $transport = $this->fakeActionTransport();
    $registered = $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test');
    app(ExternalActions::class)->pause($registered->endpoint->id);

    app(ActionPipeline::class)->run(HookPoint::TokenMinting, new ActionContext(HookPoint::TokenMinting, []));

    $transport->assertNothingSent();
});

it('is environment-scoped — an endpoint is invisible to another environment', function (): void {
    config()->set('cbox-id.external_actions.verify_url', false);

    $id = $this->runAsEnvironment('env_a', fn (): string => $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.test')->endpoint->id);

    $this->runAsEnvironment('env_b', function () use ($id): void {
        expect(ExternalActionEndpoint::query()->whereKey($id)->first())->toBeNull()
            ->and(app(ExternalActions::class)->active(HookPoint::TokenMinting))->toHaveCount(0);
    });
})->group('isolation');
