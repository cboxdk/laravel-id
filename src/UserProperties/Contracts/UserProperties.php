<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Contracts;

use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\UserProperties\ValueObjects\PropertySnapshot;

interface UserProperties
{
    public function read(string $clientId, string $userId, string $namespace): PropertySnapshot;

    public function patch(string $clientId, string $userId, string $namespace, PropertyPatch $patch): PropertySnapshot;
}
