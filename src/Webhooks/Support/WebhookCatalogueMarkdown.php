<?php

declare(strict_types=1);

namespace Cbox\Id\Webhooks\Support;

use Cbox\Id\Webhooks\Enums\WebhookEventType;
use Cbox\Id\Webhooks\ValueObjects\WebhookEventDescriptor;

/**
 * Renders {@see WebhookEventType::catalogue()} as the Markdown tables the docs publish,
 * so the documented list is generated from the enum rather than kept beside it. The
 * package's own test suite fails when `docs/reference/webhook-events.md` no longer
 * matches; a host can render the same tables into its own docs.
 */
class WebhookCatalogueMarkdown
{
    public function render(): string
    {
        $out = [];
        $group = null;

        foreach (WebhookEventType::catalogue() as $entry) {
            if ($entry->group !== $group) {
                if ($group !== null) {
                    $out[] = '';
                }

                $group = $entry->group;
                $out[] = '### '.$group->label();
                $out[] = '';
                $out[] = '| Event | Status | Description |';
                $out[] = '|---|---|---|';
            }

            $out[] = '| `'.$entry->name().'` | '.$this->status($entry).' | '.str_replace('|', '\\|', $entry->description).' |';
        }

        return implode("\n", $out)."\n";
    }

    private function status(WebhookEventDescriptor $entry): string
    {
        if (! $entry->emitted) {
            return 'not emitted';
        }

        if ($entry->supersededBy !== null) {
            return 'legacy → `'.$entry->supersededBy->value.'`';
        }

        return 'current';
    }
}
