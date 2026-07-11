<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\ValueObjects;

/**
 * Who is asking — a user, a service account, or any principal type.
 */
final readonly class Subject
{
    public function __construct(
        public string $type,
        public string $id,
    ) {}

    public static function user(string $id): self
    {
        return new self('user', $id);
    }

    public static function service(string $id): self
    {
        return new self('service', $id);
    }
}
