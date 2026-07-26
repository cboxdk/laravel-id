<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\Contracts;

use Cbox\Id\ExternalActions\Enums\HookPoint;
use Cbox\Id\ExternalActions\ValueObjects\ActionContext;

/**
 * The typed payload one hook point hands to its actions.
 *
 * Each hook point has exactly one payload class, and that class — not a call site
 * assembling an array — decides the wire shape. The shape is a published contract
 * (receiving endpoints parse it), so it lives somewhere a change to it is a visible,
 * reviewable edit to a value object rather than an invisible edit to an array
 * literal buried in a service.
 *
 * `toPayload()` produces the `array<string, mixed>` that {@see ActionContext} carries
 * and the transport serializes. Keys are snake_case, and a null-valued key is still
 * present — a receiver can tell "absent because this hook point has no such field"
 * from "present and null".
 */
interface HookPayload
{
    public function hookPoint(): HookPoint;

    /**
     * @return array<string, mixed>
     */
    public function toPayload(): array;
}
