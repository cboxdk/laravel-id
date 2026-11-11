<?php

declare(strict_types=1);

namespace Cbox\Id\Directory;

use Cbox\Id\Directory\Contracts\DeprovisioningPolicy;
use Cbox\Id\Directory\Enums\DeprovisioningMode;
use Cbox\Id\Directory\Models\Directory;
use Cbox\Id\Organization\Models\Environment;

/**
 * The deprovisioning mode of the directory's ENVIRONMENT.
 *
 * Per environment rather than per directory, because the mode answers "whose is the
 * account", and that is a property of the realm: a directory belongs to one organization,
 * and an organization administrator in a shared environment must not be able to choose
 * the mode that deactivates accounts other organizations rely on.
 *
 * Read from `environments.settings.directory.deprovisioning`, then from
 * `cbox-id.directory.deprovisioning`, then {@see DeprovisioningMode::Account}. A value
 * that is not a known mode is ignored at its level, so a typo falls through to the next
 * one instead of silently changing what a deprovision does.
 */
class EnvironmentDeprovisioningPolicy implements DeprovisioningPolicy
{
    /** Where the mode lives in an environment's `settings`. */
    public const string SETTINGS_KEY = 'directory.deprovisioning';

    public function modeFor(Directory $directory): DeprovisioningMode
    {
        return $this->parse($this->environmentSetting($directory))
            ?? $this->parse(config('cbox-id.directory.deprovisioning'))
            ?? DeprovisioningMode::Account;
    }

    private function environmentSetting(Directory $directory): mixed
    {
        $environmentId = $directory->getAttribute('environment_id');

        if (! is_string($environmentId) || $environmentId === '') {
            return null;
        }

        // The Environment model is the boundary itself, not environment-owned, so this
        // lookup is unscoped by design — the same read the issuer resolver makes.
        $environment = Environment::query()->find($environmentId);

        return $environment === null ? null : data_get($environment->settings, self::SETTINGS_KEY);
    }

    private function parse(mixed $value): ?DeprovisioningMode
    {
        return is_string($value) ? DeprovisioningMode::tryFrom(strtolower(trim($value))) : null;
    }
}
