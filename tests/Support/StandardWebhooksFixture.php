<?php

declare(strict_types=1);

namespace Cbox\Id\Tests\Support;

use JsonException;

/**
 * Reader for `tests/Fixtures/Webhooks/standard-webhooks.json` — the Standard Webhooks
 * counterpart of {@see WebhookSignatureFixture}. Its first case is the specification
 * repository's own published vector, so the sender and the verifier are held to the
 * spec authors' bytes rather than to a formula this repository wrote down twice.
 */
final class StandardWebhooksFixture
{
    /**
     * @return array{signed_payload_template: string, signature_entry_template: string, cases: list<array<string, mixed>>}
     *
     * @throws JsonException
     */
    public static function document(): array
    {
        /** @var array{signed_payload_template: string, signature_entry_template: string, cases: list<array<string, mixed>>} */
        return json_decode(
            (string) file_get_contents(dirname(__DIR__).'/Fixtures/Webhooks/standard-webhooks.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    /**
     * Every case, keyed by name — ready to hand straight to a Pest dataset.
     *
     * @return array<string, array{0: array<string, mixed>}>
     *
     * @throws JsonException
     */
    public static function dataset(): array
    {
        $dataset = [];

        foreach (self::document()['cases'] as $case) {
            /** @var string $name */
            $name = $case['name'];
            $dataset[$name] = [$case];
        }

        return $dataset;
    }
}
