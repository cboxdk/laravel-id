<?php

declare(strict_types=1);

namespace Cbox\Id\ExternalActions\ValueObjects;

use Cbox\Id\ExternalActions\Contracts\HookPayload;
use Cbox\Id\ExternalActions\Enums\HookPoint;

/**
 * The immutable context handed to every action at a hook point. `payload` carries
 * the point-specific data, whose shape each hook point's {@see HookPayload} value
 * object defines — for {@see HookPoint::TokenMinting} the requesting `client_id`, the
 * `subject`/`user_id`, `organization_id`, the granted `scopes`, a coarse `grant` kind
 * (`user` | `client_credentials`), and a read-only view of the base `claims` about to
 * be signed. An action reads this; it never mutates it (it returns an
 * {@see ActionResult} instead).
 *
 * Prefer {@see for()} over the array constructor: it takes the typed payload, so the
 * hook point and its payload cannot be mismatched and no call site invents a key.
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

    /**
     * The context for a typed payload. The payload names its own hook point, so this
     * is the only construction that cannot disagree with itself.
     */
    public static function for(HookPayload $payload): self
    {
        return new self($payload->hookPoint(), $payload->toPayload());
    }

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
