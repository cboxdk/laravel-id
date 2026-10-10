<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

/**
 * The start of a connect flow: where to send the person, and what the host must keep in
 * their session until they come back ({@see PipeConnectState}).
 */
readonly class PipeAuthorization
{
    public function __construct(
        public string $url,
        public PipeConnectState $state,
    ) {}
}
