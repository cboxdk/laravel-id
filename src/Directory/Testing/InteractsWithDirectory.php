<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Testing;

use Cbox\Id\Directory\Contracts\Directories;
use Cbox\Id\Directory\ValueObjects\RegisteredDirectory;

trait InteractsWithDirectory
{
    protected function makeDirectory(string $organizationId, string $name = 'Okta'): RegisteredDirectory
    {
        return app(Directories::class)->register($organizationId, $name);
    }
}
