<?php

declare(strict_types=1);

namespace Cbox\Id\Kernel\Authorization\Schema;

use RuntimeException;

/**
 * Internal to {@see SchemaParser}: one line that does not parse. The parser turns it into
 * a {@see SchemaError} on that line and goes on to the next, so every line is reported.
 *
 * @internal
 */
final class SchemaSyntaxError extends RuntimeException {}
