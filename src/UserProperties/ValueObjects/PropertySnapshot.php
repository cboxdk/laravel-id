<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\ValueObjects;

use stdClass;

readonly class PropertySnapshot
{
    public function __construct(
        public string $userId = '',
        public string $namespace = '',
        public stdClass $data = new stdClass,
        public int $version = 0,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return ['user_id' => $this->userId, 'namespace' => $this->namespace, 'data' => $this->data, 'version' => $this->version];
    }
}
