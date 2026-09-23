<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\ValueObjects;

use Cbox\Id\Webhooks\Enums\WebhookEventGroup;
use Cbox\Id\Webhooks\Enums\WebhookEventType;

/**
 * One entry of the webhook catalogue, as a console, an API or a docs page renders it.
 * Built only by {@see WebhookEventType::catalogue()}; every field is derived from the
 * enum case, so there is one place an event is described.
 */
readonly class WebhookEventDescriptor
{
    public function __construct(
        public WebhookEventType $type,
        public WebhookEventGroup $group,
        public string $label,
        public string $description,
        public ?WebhookEventType $supersededBy,
        public bool $emitted,
    ) {}

    /** The wire name: the `type` a delivery carries and a subscription names. */
    public function name(): string
    {
        return $this->type->value;
    }

    /**
     * Kept for subscribers that already use it, but a newer event carries the same fact
     * in a better shape. Still delivered when {@see $emitted}; not offered to new
     * subscriptions.
     */
    public function isLegacy(): bool
    {
        return $this->supersededBy !== null;
    }

    /** Whether a subscription picker should offer it: emitted, and not superseded. */
    public function isOffered(): bool
    {
        return $this->emitted && ! $this->isLegacy();
    }

    /**
     * The serialization edge — a JSON catalogue endpoint or a page's props.
     *
     * @return array{name: string, group: string, group_label: string, label: string, description: string, superseded_by: string|null, emitted: bool, offered: bool}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name(),
            'group' => $this->group->value,
            'group_label' => $this->group->label(),
            'label' => $this->label,
            'description' => $this->description,
            'superseded_by' => $this->supersededBy?->value,
            'emitted' => $this->emitted,
            'offered' => $this->isOffered(),
        ];
    }
}
