<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Testing;

use Cbox\Id\ExternalActions\Contracts\ActionTransport;
use Cbox\Id\ExternalActions\Models\ExternalActionEndpoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;
use Cbox\Id\ExternalActions\ValueObjects\ActionResult;
use PHPUnit\Framework\Assert;

/**
 * In-memory {@see ActionTransport} for tests: it records every send and returns a
 * programmed {@see ActionResult} instead of making a network call, so the pipeline
 * and the token hook can be tested without an HTTP endpoint. By default it continues
 * (allow, no enrichment); use {@see willEnrich()} / {@see willDeny()} to script a reply.
 */
class FakeActionTransport implements ActionTransport
{
    private ActionResult $result;

    /** @var list<array{endpoint: string, url: string, context: ActionContext}> */
    public array $sent = [];

    public function __construct()
    {
        $this->result = ActionResult::continue();
    }

    /**
     * @param  array<string, mixed>  $enrichment
     */
    public function willEnrich(array $enrichment): self
    {
        $this->result = ActionResult::continue($enrichment);

        return $this;
    }

    public function willDeny(string $reason = 'denied by fake action'): self
    {
        $this->result = ActionResult::deny($reason);

        return $this;
    }

    public function send(ExternalActionEndpoint $endpoint, ActionContext $context): ActionResult
    {
        $this->sent[] = ['endpoint' => $endpoint->id, 'url' => $endpoint->url, 'context' => $context];

        return $this->result;
    }

    public function assertSent(): void
    {
        Assert::assertNotEmpty($this->sent, 'Expected an external action to have been called, but none was.');
    }

    public function assertNothingSent(): void
    {
        Assert::assertSame([], $this->sent, 'Expected no external action calls.');
    }
}
