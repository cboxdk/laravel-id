<?php

declare(strict_types=1);

namespace Cbox\Id\Api\Contracts;

use Cbox\Id\Api\Scim\DirectoryScimGroupResources;

/**
 * The SCIM `/Groups` endpoint's operations (RFC 7643 §4.2, RFC 7644 §3), shared by
 * `GroupController` and `/Bulk`. Bound to
 * {@see DirectoryScimGroupResources}.
 */
interface ScimGroupResources extends ScimResourceEndpoint {}
