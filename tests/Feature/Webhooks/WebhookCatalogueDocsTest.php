<?php

declare(strict_types=1);

use Cbox\Id\Webhooks\Support\WebhookCatalogueMarkdown;

/**
 * The published event list is generated from the enum, never maintained beside it. When
 * this fails, regenerate the block between the markers in
 * docs/reference/webhook-events.md from `(new WebhookCatalogueMarkdown)->render()`.
 */
it('publishes exactly the catalogue the enum describes', function (): void {
    $doc = (string) file_get_contents(dirname(__DIR__, 3).'/docs/reference/webhook-events.md');

    $start = strpos($doc, "<!-- catalogue:start -->\n");
    $end = strpos($doc, '<!-- catalogue:end -->');

    expect($start)->not->toBeFalse()
        ->and($end)->not->toBeFalse();

    $published = substr($doc, (int) $start + strlen("<!-- catalogue:start -->\n"), (int) $end - (int) $start - strlen("<!-- catalogue:start -->\n"));

    expect($published)->toBe((new WebhookCatalogueMarkdown)->render());
});
