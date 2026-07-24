<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * The immutable context handed to every action at a hook point. `payload` carries
 * the point-specific data — for {@see HookPoint::TokenMinting} that is the requesting
 * `client_id`, the `subject`/`user_id`, `organization_id`, the granted `scopes`, a
 * coarse `grant` kind (`user` | `client_credentials`), and a read-only view of the
 * base `claims` about to be signed. An action reads this; it never mutates it (it
 * returns an {@see ActionResult} instead).
 */
readonly class ActionContext
{
    /**
     * @param  array<string, mixed>  $payload
     */
    public function __construct(
        public HookPoint $hookPoint,
        public array $payload,
    ) {}

    public function string(string $key): ?string
    {
        $value = $this->payload[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return ['hook' => $this->hookPoint->value] + $this->payload;
    }
}
