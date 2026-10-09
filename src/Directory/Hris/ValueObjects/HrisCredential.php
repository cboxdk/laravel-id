<?php

declare(strict_types=1);

namespace Cbox\Id\Directory\Hris\ValueObjects;

/**
 * One value an administrator supplies to connect an HR system, in the CONNECTOR's own key.
 *
 * `secret` decides how a form draws it and whether it may ever be shown again: an API key
 * is typed once, sealed, and never read back, while a subdomain is ordinary configuration.
 * `required` is false only where the connector has a working default or an alternative
 * (Workday takes either an integration user's password or an OAuth refresh token).
 */
readonly class HrisCredential
{
    public function __construct(
        public string $key,
        public string $label,
        public string $help,
        public string $example = '',
        public bool $secret = false,
        public bool $required = true,
    ) {}
}
