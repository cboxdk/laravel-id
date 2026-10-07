<?php

declare(strict_types=1);

namespace Cbox\Id\Platform\ValueObjects;

/**
 * Who minted a management key, and from what.
 *
 * `createdByType`/`createdById` name the principal in the host's own vocabulary — a person
 * (`organization_member`), an operator, or another key (`environment_key`). `parentKeyId`
 * is set when a key minted this one, so revoking the parent can find what it made;
 * `rotatedFromId` when this key replaces another. `stepUpPolicy` is the host's opaque
 * rule set for which of this key's actions need a person's approval — the package stores
 * it and never reads it.
 *
 * `new KeyProvenance` — nobody known, no parent, no policy — is the meaningful default:
 * it is exactly what every key minted before this existed records.
 */
final readonly class KeyProvenance
{
    /**
     * @param  array<string, mixed>|null  $stepUpPolicy
     */
    public function __construct(
        public ?string $createdByType = null,
        public ?string $createdById = null,
        public ?string $parentKeyId = null,
        public ?string $rotatedFromId = null,
        public ?string $description = null,
        public ?array $stepUpPolicy = null,
    ) {}

    /**
     * The columns this provenance writes.
     *
     * @return array{created_by_type: string|null, created_by_id: string|null, parent_key_id: string|null, rotated_from_id: string|null, description: string|null, step_up_policy: array<string, mixed>|null}
     */
    public function toAttributes(): array
    {
        return [
            'created_by_type' => $this->createdByType,
            'created_by_id' => $this->createdById,
            'parent_key_id' => $this->parentKeyId,
            'rotated_from_id' => $this->rotatedFromId,
            'description' => $this->description,
            'step_up_policy' => $this->stepUpPolicy,
        ];
    }
}
