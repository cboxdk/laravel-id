<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Contracts;

use Cbox\Id\Api\Scim\DirectoryScimUserResources;

/**
 * The SCIM `/Users` endpoint's operations (RFC 7643 §4.1, RFC 7644 §3), shared by
 * `UserController` and `/Bulk`. Bound to
 * {@see DirectoryScimUserResources}.
 */
interface ScimUserResources extends ScimResourceEndpoint {}
