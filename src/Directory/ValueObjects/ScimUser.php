<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\ValueObjects;

/**
 * A SCIM 2.0 User resource, already parsed from the wire.
 */
final readonly class ScimUser
{
    /**
     * @param  array<string, mixed>  $raw
     */
    public function __construct(
        public string $externalId,
        public string $userName,
        public ?string $email = null,
        public ?string $displayName = null,
        public bool $active = true,
        public array $raw = [],
    ) {}
}
