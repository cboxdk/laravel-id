<?php

declare(strict_types=1);

namespace Cbox\Id\Provisioning\Exceptions;

use RuntimeException;

/**
 * A provisioning connection that cannot authenticate, because something it needs was
 * never supplied — not because anything was unreachable.
 *
 * The distinction is the whole point. An unreachable token endpoint is transient and the
 * drain should retry it; a MISSING one is permanent, and retrying it exhausts every queued
 * joiner and leaver against a field that no amount of waiting will fill in. Both used to
 * be caught by the same handler and both came out transient.
 */
final class MisconfiguredScimConnection extends RuntimeException {}
