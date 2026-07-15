<?php

declare(strict_types=1);

namespace Cbox\Id\SamlIdp\Enums;

/**
 * Lifecycle of a registered SAML service provider. Only {@see self::Active}
 * providers may receive assertions — every other state is refused (deny-by-default).
 */
enum ServiceProviderStatus: string
{
    case Active = 'active';
    case Disabled = 'disabled';
}
