<?php

declare(strict_types=1);

namespace Cbox\Id\AccessControl\Enums;

/**
 * Where a role's definition came from — an admin authoring it in the console
 * ({@see self::Manual}) or an app declaring it through its manifest
 * ({@see self::Manifest}). Manifest roles are read-only in the console: the app is
 * their source of truth.
 */
enum RoleSource: string
{
    case Manual = 'manual';
    case Manifest = 'manifest';
}
