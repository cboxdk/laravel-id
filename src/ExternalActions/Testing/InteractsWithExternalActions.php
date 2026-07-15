<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Testing;

use Cbox\Id\ExternalActions\Contracts\ActionPipeline;
use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Contracts\ExternalActions;
use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\RegisteredActionEndpoint;

/**
 * Drop-in test ergonomics for external actions / inline hooks:
 *
 *     use Cbox\Id\ExternalActions\Testing\InteractsWithExternalActions;
 *
 *     uses(InteractsWithExternalActions::class);
 *
 *     it('enriches the token', function () {
 *         $transport = $this->fakeActionTransport()->willEnrich(['tenant_tier' => 'pro']);
 *         $this->registerActionEndpoint(HookPoint::TokenMinting, 'https://hook.example.com');
 *         // ... issue a token, assert the claim ...
 *     });
 */
trait InteractsWithExternalActions
{
    /**
     * Swap the real HTTP transport for an in-memory fake and return it, so a test can
     * script the reply and read back what was sent — no network.
     */
    protected function fakeActionTransport(): FakeActionTransport
    {
        $fake = new FakeActionTransport;

        app()->instance(ActionTransport::class, $fake);
        // Rebuild the pipeline so it picks up the fake transport. Call this before
        // the code under test resolves the pipeline (as with Http::fake()).
        app()->forgetInstance(ActionPipeline::class);

        return $fake;
    }

    protected function registerActionEndpoint(HookPoint $hookPoint, string $url, ?string $organizationId = null): RegisteredActionEndpoint
    {
        return app(ExternalActions::class)->register($hookPoint, $url, $organizationId);
    }
}
