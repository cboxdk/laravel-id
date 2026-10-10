<?php

declare(strict_types=1);

namespace Cbox\Id\Pipes\ValueObjects;

/**
 * A value an administrator may set on a pipe because it is per installation rather than
 * per provider: Microsoft's tenant, Salesforce's login domain.
 *
 * Every parameter has a DEFAULT that works for most installations, so configuring a pipe
 * never requires one — and a PATTERN, because the value is substituted into an endpoint
 * the platform then sends a client secret to. A tenant of `evil.test/x?` would otherwise
 * be a way to post the secret somewhere else.
 */
readonly class PipeParameter
{
    public function __construct(
        public string $key,
        public string $label,
        public string $default,
        /** A full-match PCRE, delimiters included. */
        public string $pattern,
        public string $help = '',
    ) {}

    public function accepts(string $value): bool
    {
        return $value !== '' && preg_match($this->pattern, $value) === 1;
    }
}
