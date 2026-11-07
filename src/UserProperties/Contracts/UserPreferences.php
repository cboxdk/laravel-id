<?php

declare(strict_types=1);

namespace Cbox\Id\UserProperties\Contracts;

use Cbox\Id\UserProperties\ValueObjects\PropertyPatch;
use Cbox\Id\UserProperties\ValueObjects\PropertySnapshot;

/**
 * First-party identity host access to the authenticated subject's own preferences.
 * The host must authenticate the subject and derive userId from its trusted session.
 * Never expose this contract through an OAuth client or accept userId from a form.
 */
interface UserPreferences
{
    public function read(string $userId): PropertySnapshot;

    public function patch(string $userId, PropertyPatch $patch): PropertySnapshot;
}
