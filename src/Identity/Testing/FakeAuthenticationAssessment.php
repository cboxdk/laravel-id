<?php

declare(strict_types=1);

namespace Cbox\Id\Identity\Testing;

use Cbox\Id\Identity\Contracts\AuthenticationAssessment;
use Cbox\Id\Identity\Exceptions\AuthenticationStepUpRequired;
use Cbox\Id\Identity\ValueObjects\VerifiedAuthentication;
use LogicException;

/** Explicit decisions only: an exhausted fake must not silently admit a login. */
class FakeAuthenticationAssessment implements AuthenticationAssessment
{
    /** @var list<VerifiedAuthentication> */
    public array $calls = [];

    /** @param list<AuthenticationStepUpRequired|null> $decisions Null explicitly permits ordinary policy. */
    public function __construct(private array $decisions) {}

    public function assertAllowed(VerifiedAuthentication $authentication): void
    {
        $this->calls[] = $authentication;
        if ($this->decisions === []) {
            throw new LogicException('No authentication assessment decision was queued.');
        }
        $decision = array_shift($this->decisions);
        if ($decision !== null) {
            throw $decision;
        }
    }
}
